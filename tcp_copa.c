#include <linux/module.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <net/tcp.h>

#define COPA_VERSION 1

/* Fixed-point scale for deltaParam (like mvfst's double deltaParam_). */
#define COPA_SCALE 8
#define COPA_UNIT (1U << COPA_SCALE)

#define copa_param(sk, name) (copa_##name)

/* minRTT window length */
static u32 copa_min_rtt_win_sec = 10;

/* Minimum cwnd floor */
static u32 copa_cwnd_min_target = 4;

/* Use min_rtt to help adapt TSO burst size, with smaller min_rtt resulting
 * in bigger TSO bursts. We cut the RTT-based allowance in half
 * for every 2^9 usec (aka 512 us) of RTT, so that the RTT-based allowance
 * is below 1500 bytes after 6 * ~500 usec = 3ms.
 */
static u32 copa_tso_rtt_shift = 9;

/* deltaParam in COPA_UNIT fixed point.
 * mvfst default is 0.05 -> 0.05*256=12.8 => 13
 * I use a smaller value here as low delay sensitivity causes an overshoot of the pacing rate, leading to sawtooth behaviour
 */
static u32 copa_delta_param_fp = 8;

/* Use standing RTT mechanism (1) or lrtt-minRTT (0). */
static u32 copa_use_rtt_standing = 0;

/* Cap velocity (keep huge for "true" behavior; still module param) */
static u32 copa_velocity_max = 99999;

/* Cap acked packets used in cwnd update to limit huge bursts */
static u32 copa_acked_pkts_cap = 256;

enum copa_dir {
	COPA_DIR_NONE = 0,
	COPA_DIR_UP   = 1,
	COPA_DIR_DOWN = 2,
};

struct copa {
	u64	standing_subwin_start_us; /* start time of standing-RTT sub-window */
	u64	last_dir_update_us;	 /* last time we updated cwnd direction */
	u64	last_cwnd_double_us;	 /* last time cwnd was doubled */
	u32	min_rtt_us;		 /* min RTT sample over minRTT window */
	u32	min_rtt_stamp;		 /* jiffies32 when min_rtt_us was last updated */
	u32	standing_rtt_us[2];	 /* per-half-window standing RTT min */
	u32	velocity;		 /* velocity/gain used to adjust cwnd */
	u32	last_recorded_cwnd_bytes; /* cwnd (bytes) recorded at last direction update */
	u32	init_cwnd;		 /* initial cwnd (units per implementation) */
	u32	prior_cwnd;		 /* saved cwnd from prior phase/epoch */
	u32	has_seen_rtt:1,		 /* have we observed at least one valid RTT sample? */
		idle_restart:1,		 /* did we restart after an idle period? */
		initialized:1,		 /* has copa init been run / state valid? */
		slow_start:1,		 /* currently in slow start growth phase? */
		unused:28;		 /* spare bits */

	u8	standing_subwin_idx;	 /* current standing-RTT half-window index (0/1) */
	u8	direction;		 /* cwnd direction (e.g., up/down) */
	u8	dir_same_cnt;		 /* consecutive updates with same direction */
};

static inline u32 copa_srtt_us(const struct tcp_sock *tp)
{
	return tp->srtt_us ? max(tp->srtt_us >> 3, 1U) : USEC_PER_MSEC;
}

static void copa_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct copa *ca = inet_csk_ca(sk);
	u32 rtt_us, expire;
	bool expired;

	if (rs->rtt_us < 0 || rs->is_ack_delayed)
		return;

	rtt_us = max_t(u32, (u32)rs->rtt_us, 1U);

	if (!ca->has_seen_rtt) {
		ca->has_seen_rtt = 1;
		ca->min_rtt_us = rtt_us;
		ca->min_rtt_stamp = tcp_jiffies32;
		return;
	}

	expire = ca->min_rtt_stamp + copa_param(sk, min_rtt_win_sec) * HZ;
	expired = after(tcp_jiffies32, expire);

	if (rtt_us <= ca->min_rtt_us || expired) {
		ca->min_rtt_us = rtt_us;
		ca->min_rtt_stamp = tcp_jiffies32;
	}
}


static void copa_update_standing_rtt(struct sock *sk, u32 rtt_us, u64 now_us,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct copa *ca = inet_csk_ca(sk);
	u32 srtt_us, win_us, subwin_us;

	if (rs && rs->is_ack_delayed)
		return;

	rtt_us = max_t(u32, rtt_us, 1U);

	srtt_us = copa_srtt_us(tp);
	win_us  = copa_param(sk, use_rtt_standing) ? srtt_us : max(srtt_us / 2, 1U);
	subwin_us = max(win_us / 2, 1U);

	if (unlikely(!ca->standing_subwin_start_us)) {
		ca->standing_subwin_start_us = now_us;
		ca->standing_subwin_idx = 0;
		ca->standing_rtt_us[0] = rtt_us;
		ca->standing_rtt_us[1] = ~0U;
		return;
	}

	while (now_us - ca->standing_subwin_start_us >= (u64)subwin_us) {
		ca->standing_subwin_start_us += (u64)subwin_us;
		ca->standing_subwin_idx ^= 1;
		ca->standing_rtt_us[ca->standing_subwin_idx] = ~0U;
	}

	ca->standing_rtt_us[ca->standing_subwin_idx] =
		min(ca->standing_rtt_us[ca->standing_subwin_idx], rtt_us);
}

static inline u32 copa_get_standing_rtt_us(const struct copa *ca, u32 fallback_rtt_us)
{
	u32 a = ca->standing_rtt_us[0];
	u32 b = ca->standing_rtt_us[1];
	u32 best = min(a, b);

	if (best == ~0U)
		best = (a != ~0U) ? a : (b != ~0U ? b : fallback_rtt_us);

	return max_t(u32, best, 1U);
}

/* direction/velocity update once per RTT */
static void copa_check_and_update_direction(struct sock *sk, u64 now_us, u32 cwnd_bytes)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct copa *ca = inet_csk_ca(sk);
	u32 srtt = copa_srtt_us(tp);

	if (!ca->last_dir_update_us) {
		ca->last_dir_update_us = now_us;
		ca->last_recorded_cwnd_bytes = cwnd_bytes;
		ca->direction = COPA_DIR_NONE;
		ca->dir_same_cnt = 0;
		ca->velocity = max(ca->velocity, 1U);
		return;
	}

	if (now_us - ca->last_dir_update_us < (u64)srtt)
		return;

	
	u8 new_dir = (cwnd_bytes > ca->last_recorded_cwnd_bytes) ?
				COPA_DIR_UP : COPA_DIR_DOWN;

	if (new_dir != ca->direction) {
		ca->velocity = 1;
		ca->dir_same_cnt = 0;
	} else {
		u32 thresh = copa_param(sk, use_rtt_standing) ? 4 : 3;
		ca->dir_same_cnt++;
		if (ca->dir_same_cnt >= thresh) {
			u32 vmax = max_t(u32, copa_param(sk, velocity_max), 1U);
			ca->velocity = min(ca->velocity << 1, vmax);
		}
	}
	ca->direction = new_dir;
	ca->last_dir_update_us = now_us;
	ca->last_recorded_cwnd_bytes = cwnd_bytes;
	
}

static void copa_change_direction(struct copa *ca, u8 new_dir, u64 now_us, u32 cwnd_bytes)
{
	if (ca->direction == new_dir)
		return;

	ca->direction = new_dir;
	ca->velocity = 1;
	ca->dir_same_cnt = 0;
	ca->last_dir_update_us = now_us;
	ca->last_recorded_cwnd_bytes = cwnd_bytes;
}

/* pacing from cwnd, like mvfst: refreshPacingRate(cwndBytes*2, srtt) */
static void copa_refresh_pacing_from_cwnd(struct sock *sk, u64 cwnd_bytes)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u64 rate;
	u64 maxr = READ_ONCE(sk->sk_max_pacing_rate);
	u32 srtt = copa_srtt_us(tp);

	rate = cwnd_bytes << 1;
	rate *= USEC_PER_SEC;
	do_div(rate, (u64)srtt);

	if (maxr)
		rate = min(rate, maxr);

	WRITE_ONCE(sk->sk_pacing_rate, (unsigned long)max(rate, 1ULL));
}

/* Return the number of segments copa would like in a TSO/GSO skb, given a
 * particular max gso size as a constraint. 
 */
static u32 copa_tso_segs_generic(struct sock *sk, unsigned int mss_now, u32 gso_max_size)
{
	struct copa *ca = inet_csk_ca(sk);
	u32 segs, r;
	u64 bytes;

	/* Budget a TSO/GSO burst size allowance based on bw (pacing_rate). */
	bytes = READ_ONCE(sk->sk_pacing_rate) >> READ_ONCE(sk->sk_pacing_shift);
	
	/* Budget a TSO/GSO burst size allowance based on min_rtt. For every
	 * K = 2^tso_rtt_shift microseconds of min_rtt, halve the burst.
	 * The min_rtt-based burst allowance is: 64 KBytes / 2^(min_rtt/K)
	 */
	if (copa_param(sk, tso_rtt_shift)) {
		r = ca->min_rtt_us >> copa_param(sk, tso_rtt_shift);
		if (r < BITS_PER_TYPE(u32))
			bytes += (u64)GSO_LEGACY_MAX_SIZE >> r;
	}

	if (gso_max_size > 1 + MAX_TCP_HEADER)
		bytes = min_t(u64, bytes, (u64)gso_max_size - 1 - MAX_TCP_HEADER);

	segs = max_t(u32, (u32)(bytes / mss_now),
		     sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs);
	return segs;
}

/* Custom tcp_tso_autosize() for BBR, used at transmit time to cap skb size. */
static u32 copa_tso_segs(struct sock *sk, unsigned int mss_now)
{
	return copa_tso_segs_generic(sk, mss_now, sk->sk_gso_max_size);
}

/* Save "last known good" cwnd so we can restore it after losses */
static void copa_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct copa *ca = inet_csk_ca(sk);
	ca->prior_cwnd = max(ca->prior_cwnd, tcp_snd_cwnd(tp));
}

static void copa_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct copa *ca = inet_csk_ca(sk);

	if (event == CA_EVENT_TX_START) {
		if (!tp->app_limited)
			return;
		ca->idle_restart = 1;
	}
}

static u32 copa_sndbuf_expand(struct sock *sk)
{
	return 3;
}

static void copa_main(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct copa *ca = inet_csk_ca(sk);

	u64 now_us = tp->tcp_mstamp;
	u32 rtt_us, min_rtt_us, standing_us, delay_us;
	u32 mss = tp->mss_cache;
	u32 acked_pkts;
	u64 cwnd_bytes;
	bool increase;

	if (unlikely(!ca->initialized))
		return;

	/* choose RTT sample */
	if (rs->rtt_us >= 0 && !rs->is_ack_delayed) {
		rtt_us = max_t(u32, (u32)rs->rtt_us, 1U);
		copa_update_min_rtt(sk, rs);
		copa_update_standing_rtt(sk, rtt_us, now_us, rs);
	} else {
		return;
	}

	if (!ca->has_seen_rtt || ca->min_rtt_us == 0 || ca->min_rtt_us == ~0U)
		return;

	min_rtt_us = ca->min_rtt_us;
	standing_us = copa_get_standing_rtt_us(ca, rtt_us);

	if (standing_us < min_rtt_us)
		return;

	if (copa_param(sk, use_rtt_standing))
		delay_us = standing_us - min_rtt_us;
	else
		// srtt as a fallback 
		delay_us = copa_srtt_us(tp) - min_rtt_us;

	if (delay_us == 0) {
		increase = true;
	} else {
		u64 target_rate, current_rate;

		target_rate = (u64)mss * USEC_PER_SEC * (u64)COPA_UNIT;
		do_div(target_rate,
		       (u64)max_t(u32, copa_param(sk, delta_param_fp), 1U) *
		       (u64)delay_us);

		cwnd_bytes = (u64)tcp_snd_cwnd(tp) * (u64)mss;
		current_rate = cwnd_bytes * USEC_PER_SEC;
		do_div(current_rate, (u64)max_t(u32, standing_us, 1U));

		increase = (target_rate >= current_rate);
	}

	acked_pkts = (rs->acked_sacked > 0) ? (u32)rs->acked_sacked : 1U;
	acked_pkts = min_t(u32, acked_pkts, max_t(u32, copa_param(sk, acked_pkts_cap), 1U));

	cwnd_bytes = (u64)tcp_snd_cwnd(tp) * (u64)mss;

	if (!(increase && ca->slow_start))
		copa_check_and_update_direction(sk, now_us,
			(u32)min_t(u64, cwnd_bytes, (u64)U32_MAX));

	if (increase) {
		if (ca->slow_start) {
			u32 srtt = copa_srtt_us(tp);

			if (!ca->last_cwnd_double_us) {
				ca->last_cwnd_double_us = now_us;
			} else if (now_us - ca->last_cwnd_double_us > (u64)srtt) {
				u64 new_cwnd_bytes = cwnd_bytes << 1;
				u64 clamp_bytes = (u64)tp->snd_cwnd_clamp * (u64)mss;

				new_cwnd_bytes = min(new_cwnd_bytes, clamp_bytes);
				tcp_snd_cwnd_set(tp,
					(u32)max_t(u64, new_cwnd_bytes / mss,
						   (u64)copa_param(sk, cwnd_min_target)));

				ca->last_cwnd_double_us = now_us;
				cwnd_bytes = (u64)tcp_snd_cwnd(tp) * (u64)mss;
			}
		} else {
			if (ca->direction != COPA_DIR_UP && ca->velocity > 1)
				copa_change_direction(ca, COPA_DIR_UP, now_us,
					(u32)min_t(u64, cwnd_bytes, (u64)U32_MAX));

			{
				u64 numer, denom, add_bytes;
				u64 clamp_bytes = (u64)tp->snd_cwnd_clamp * (u64)mss;

				numer  = (u64)acked_pkts * (u64)mss * (u64)mss;
				numer *= (u64)max_t(u32, ca->velocity, 1U);
				numer *= (u64)COPA_UNIT;

				denom  = (u64)max_t(u32, copa_param(sk, delta_param_fp), 1U) *
					 (u64)max_t(u64, cwnd_bytes, 1ULL);

				add_bytes = numer / denom;

				cwnd_bytes = min(cwnd_bytes + add_bytes, clamp_bytes);
				tcp_snd_cwnd_set(tp,
					(u32)max_t(u64, cwnd_bytes / mss,
						   (u64)copa_param(sk, cwnd_min_target)));
			}
		}
	} else {
		ca->slow_start = 0;

		if (ca->direction != COPA_DIR_DOWN && ca->velocity > 1)
			copa_change_direction(ca, COPA_DIR_DOWN, now_us, (u32)min_t(u64, cwnd_bytes, (u64)U32_MAX));

		{
			u64 numer, denom, red_bytes;
			u64 min_bytes = (u64)copa_param(sk, cwnd_min_target) * (u64)mss;

			numer  = (u64)acked_pkts * (u64)mss * (u64)mss;
			numer *= (u64)max_t(u32, ca->velocity, 1U);
			numer *= (u64)COPA_UNIT;

			denom  = (u64)max_t(u32, copa_param(sk, delta_param_fp), 1U) *
				 (u64)max_t(u64, cwnd_bytes, 1ULL);

			red_bytes = numer / denom;

			if (cwnd_bytes > min_bytes) {
				if (red_bytes >= cwnd_bytes - min_bytes)
					cwnd_bytes = min_bytes;
				else
					cwnd_bytes -= red_bytes;

				tcp_snd_cwnd_set(tp,
					(u32)max_t(u64, cwnd_bytes / mss,
						   (u64)copa_param(sk, cwnd_min_target)));
			}
		}
	}

	cwnd_bytes = (u64)tcp_snd_cwnd(tp) * (u64)mss;
	copa_refresh_pacing_from_cwnd(sk, cwnd_bytes);

	if (rs->delivered > 0)
		ca->idle_restart = 0;

	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
}

static void copa_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct copa *ca = inet_csk_ca(sk);

	memset(ca, 0, sizeof(*ca));

	ca->initialized = 1;
	ca->init_cwnd = min(0x7FU, tcp_snd_cwnd(tp));
	ca->prior_cwnd = ca->init_cwnd;

	ca->min_rtt_us = ~0U;
	ca->min_rtt_stamp = tcp_jiffies32;
	ca->has_seen_rtt = 0;

	memset(ca->standing_rtt_us, 0, sizeof(ca->standing_rtt_us));
	ca->standing_subwin_start_us = 0;

	ca->slow_start = 1;
	ca->last_cwnd_double_us = 0;

	ca->velocity = 1;
	ca->direction = COPA_DIR_NONE;
	ca->dir_same_cnt = 0;
	ca->last_dir_update_us = 0;
	ca->last_recorded_cwnd_bytes = (u32)min_t(u64,
		(u64)tcp_snd_cwnd(tp) * (u64)tp->mss_cache, (u64)U32_MAX);

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	copa_refresh_pacing_from_cwnd(sk, (u64)tcp_snd_cwnd(tp) * (u64)tp->mss_cache);

	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
}

static u32 copa_undo_cwnd(struct sock *sk)
{
	struct copa *ca = inet_csk_ca(sk);
	return max_t(u32, ca->prior_cwnd, copa_param(sk, cwnd_min_target));
}

static u32 copa_ssthresh(struct sock *sk)
{
	copa_save_cwnd(sk);
	return tcp_sk(sk)->snd_ssthresh;
}

static struct tcp_congestion_ops tcp_copa_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "copa",
	.owner		= THIS_MODULE,
	.init		= copa_init,
	.cong_control	= copa_main,
	.sndbuf_expand	= copa_sndbuf_expand,
	.undo_cwnd	= copa_undo_cwnd,
	.cwnd_event	= copa_cwnd_event,
	.ssthresh	= copa_ssthresh,
	.tso_segs	= copa_tso_segs,
};

static int __init copa_register(void)
{
	BUILD_BUG_ON(sizeof(struct copa) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_copa_cong_ops);
}

static void __exit copa_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_copa_cong_ops);
}

module_init(copa_register);
module_exit(copa_unregister);

MODULE_AUTHOR("Mihai Mazilu M.Mazilu@sussex.ac.uk");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP COPA (mvfst-inspired) congestion control");
MODULE_VERSION(__stringify(COPA_VERSION));