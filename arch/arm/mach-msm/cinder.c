/**
 * Cinder architecture specific code
 *
 * Contains battery interface
 * TODO: Not every MACH_MSM is an HTC battery using device, need to find a 
 * more longterm solution here.
 */

#include <linux/cinder.h>

struct battery_info_reply {
	u32 batt_id;		/* Battery ID from ADC */
	u32 batt_vol;		/* Battery voltage from ADC */
	u32 batt_temp;		/* Battery Temperature (C) from formula and ADC */
	u32 batt_current;	/* Battery current from ADC */
	u32 level;		/* formula */
	u32 charging_source;	/* 0: no cable, 1:usb, 2:AC */
	u32 charging_enabled;	/* 0: Disable, 1: Enable */
	u32 full_bat;		/* Full capacity of battery (mAh) */
};

extern int htc_battery_property_call(struct battery_info_reply *buffer);

#define CINDER_CPU_MILLIWATTS 155
#define CINDER_BATTERY_MILLIVOLTS 3700
#define CINDER_MICRO_AMP_HOURS_PER_COULOMB 278

#define CINDER_CPU_DRAW_RATE_PER_SECOND ( (CINDER_CPU_MILLIWATTS * CINDER_MICRO_AMP_HOURS_PER_COULOMB)/ CINDER_BATTERY_MILLIVOLTS )

long cinder_cpu_draw_rate_per_second()
{
	return CINDER_CPU_DRAW_RATE_PER_SECOND;
}

long cinder_max_battery_level()
{
	int ret;
	struct battery_info_reply buf;

	ret = htc_battery_property_call(&buf);
	if (ret < 0)
		return ret;
	
	return buf.full_bat;
}

long cinder_current_battery_level()
{
	int ret;
	struct battery_info_reply buf;

	ret = htc_battery_property_call(&buf);
	if (ret < 0)
		return ret;
	
	return buf.level;
}

long cinder_is_plugged_in()
{
	int ret;
	struct battery_info_reply buf;

	ret = htc_battery_property_call(&buf);
	if (ret < 0)
		return ret;
	
	return buf.charging_source;
}

