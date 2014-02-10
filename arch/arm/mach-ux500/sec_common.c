/**
 * arch/arm/mach-omap2/sec_common.c
 *
 * Copyright (C) 2010-2011, Samsung Electronics, Co., Ltd. All Rights Reserved.
 *  Written by System S/W Group, Open OS S/W R&D Team,
 *  Mobile Communication Division.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/**
 * Project Name : OMAP-Samsung Linux Kernel for Android
 *
 * Project Description :
 *
 * Comments : tabstop = 8, shiftwidth = 8, noexpandtab
 */

/**
 * File Name : sec_common.c
 *
 * File Description :
 *
 * Author : System Platform 2
 * Dept : System S/W Group (Open OS S/W R&D Team)
 * Created : 11/Mar/2011
 * Version : Baby-Raccoon
 */
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/err.h>
#include <linux/device.h>
#include <mach/hardware.h>
#include <mach/id.h>
#include <mach/io.h>

#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)

#include <plat/io.h>
#include <plat/system.h>

#include "mux.h"
#include "omap_muxtbl.h"

#include "sec_common.h"
#include "sec_param.h"
#elif defined (CONFIG_MACH_SAMSUNG_U9540)
#include <mach/sec_common.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <asm/thread_notify.h>
#include <asm/stacktrace.h>
#include <asm/mach/time.h>
#include <mach/sec_param.h>
#include <mach/system.h>
#include <mach/board-sec-ux500.h>
#include <asm/io.h>
#elif defined(CONFIG_MACH_SAMSUNG_UX500)
#include <mach/sec_common.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <asm/thread_notify.h>
#include <asm/stacktrace.h>
#include <asm/mach/time.h>
#include <asm/io.h>
#include <mach/sec_common.h>
#include <mach/sec_param.h>
#include <mach/board-sec-ux500.h>
#ifdef CONFIG_SAMSUNG_PANIC_DISPLAY_PMIC
#include <mach/sec_pmic.h>
#endif
#ifdef CONFIG_SAMSUNG_PANIC_LCD_DISPLAY
#include "sec_debug/khb_main.h"
#endif
#if defined(CONFIG_SAMSUNG_ADD_GAFORENSICINFO)
#include <mach/sec_gaf.h>
#include <linux/sched.h>
#endif
#endif

#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/ptrace.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>


#if defined(CONFIG_ARCH_OMAP3)
#define SEC_REBOOT_MODE_ADDR		(OMAP343X_CTRL_BASE + 0x0918)
#define SEC_REBOOT_FLAG_ADDR		(OMAP343X_CTRL_BASE + 0x09C4)
#define SEC_REBOOT_CMD_ADDR		NULL
#elif defined(CONFIG_ARCH_OMAP4)
#define OMAP_SW_BOOT_CFG_ADDR		0x4A326FF8
#define SEC_REBOOT_MODE_ADDR		(OMAP_SW_BOOT_CFG_ADDR)
#define SEC_REBOOT_FLAG_ADDR		(OMAP_SW_BOOT_CFG_ADDR - 0x04)
/* -0x08/-0x0C are reserved for debug */
#define SEC_REBOOT_CMD_ADDR		(OMAP_SW_BOOT_CFG_ADDR - 0x10)
#elif defined (CONFIG_MACH_SAMSUNG_U9540) || defined (CONFIG_MACH_SAMSUNG_U8500) 
#else
#error "unsupported mach-type for OMAP-Samsung"
#endif



struct class *sec_class;
EXPORT_SYMBOL(sec_class);

struct class *camera_class;
EXPORT_SYMBOL(camera_class);

void (*sec_set_param_value) (int idx, void *value) = NULL;
EXPORT_SYMBOL(sec_set_param_value);

void (*sec_get_param_value) (int idx, void *value) = NULL;
EXPORT_SYMBOL(sec_get_param_value);

u32 sec_bootmode;
EXPORT_SYMBOL(sec_bootmode);

static __init int setup_boot_mode(char *opt)
{
	sec_bootmode = (u32) memparse(opt, &opt);
	return 0;
}

__setup("bootmode=", setup_boot_mode);

#if defined(CONFIG_MACH_JANICE_CHN) || defined (CONFIG_MACH_GAVINI)
u32 sec_lpm_bootmode;
EXPORT_SYMBOL(sec_lpm_bootmode);

static __init int setup_lpm_boot_mode(char *opt)
{
	sec_lpm_bootmode = (u32) memparse(opt, &opt);
	return 0;
}

__setup("lpm_boot=", setup_lpm_boot_mode);
#endif

u32 sec_dbug_level;
EXPORT_SYMBOL(sec_dbug_level);

static __init int setup_dbug_level(char *str)
{
	if (get_option(&str, &sec_dbug_level) != 1)
		sec_dbug_level = 0;

	return 0;
}

__setup("androidboot.debug_level=", setup_dbug_level);

u32 set_default_param;
EXPORT_SYMBOL(set_default_param);

static __init int setup_default_param(char *str)
{
	if (get_option(&str, &set_default_param) != 1)
		set_default_param = 0;

	return 0;
}

__setup("set_default_param=", setup_default_param);


/* movinand checksum */
static struct device *sec_checksum;
static unsigned int sec_checksum_pass;
static unsigned int sec_checksum_done;

static __init int setup_checksum_pass(char *str)
{
	if (get_option(&str, &sec_checksum_pass) != 1)
		sec_checksum_pass = 0;

	return 0;
}

__setup("checksum_pass=", setup_checksum_pass);

static __init int setup_checksum_done(char *str)
{
	if (get_option(&str, &sec_checksum_done) != 1)
		sec_checksum_done = 0;

	return 0;
}

__setup("checksum_done=", setup_checksum_done);

static ssize_t checksum_pass_show(struct device *dev,
		    struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", (u8) sec_checksum_pass);
}

static ssize_t checksum_done_show(struct device *dev,
		    struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", (u8) sec_checksum_done);
}

struct sec_reboot_code {
	char *cmd;
	int mode;
};

static int __sec_common_reboot_call(struct notifier_block *this,
				    unsigned long code, void *cmd)
{
	int mode = REBOOT_MODE_NONE;
	int temp_mode;
	int default_switchsel = 1;
	size_t i, n;
	unsigned long value;
	int debug_level;
	struct sec_reboot_code reboot_tbl[] = {
		{"arm11_fota", REBOOT_MODE_ARM11_FOTA},
		{"arm9_fota", REBOOT_MODE_ARM9_FOTA},
		{"recovery", REBOOT_MODE_RECOVERY},
		{"cp_crash", REBOOT_MODE_CP_CRASH},
		{"download", REBOOT_MODE_DOWNLOAD},
		{"prerecovery_done", REBOOT_MODE_RECOVERY},
		{"prerecovery", REBOOT_MODE_PRERECOVERY},
	};

	printk(KERN_INFO "%s: code: 0x%lx, cmd: %s\n", __func__, code,
	       (cmd) ? (char *)cmd : "none");

	if ((code == SYS_RESTART) && cmd) {
		n = ARRAY_SIZE(reboot_tbl);
		for (i = 0; i < n; i++) {
			if (!strcmp((char *)cmd, reboot_tbl[i].cmd)) {
				if(!strcmp((char *)cmd, "recovery")) {
					u8 prerecovery_state = 0;
					printk(KERN_INFO "%s: clear prerecovery flag=%d\n", __func__,
					       prerecovery_state);
					sec_set_param_value(__FORCE_PRERECOVERY, &prerecovery_state);
				}
				mode = reboot_tbl[i].mode;
				break;
			} else if(!strncmp(cmd, "sud", 3)) {
				mode = REBOOT_MODE_DOWNLOAD;
				break;
			} else if (!strncmp(cmd, "debug", 5)
				&& !kstrtoul(cmd + 5, 0, &value)) {
				mode = REBOOT_MODE_NONE;

				switch ((int)value) {
				case DEBUG_LEVEL_LOW:
					debug_level = 0;
					break;
				case DEBUG_LEVEL_MID:
					debug_level = 1;
					break;
				case DEBUG_LEVEL_HIGH:
					debug_level = 2;
					break;
				default:
					debug_level = -1;
				}
				if (sec_set_param_value && debug_level != -1)
					sec_set_param_value(__DEBUG_LEVEL, &debug_level);
			}
		}
	}

	if (code != SYS_POWER_OFF) {
		if (sec_get_param_value && sec_set_param_value) {
			/* in case of RECOVERY mode we set switch_sel
			 * with default value */
			sec_get_param_value(__REBOOT_MODE, &temp_mode);
			if (temp_mode == REBOOT_MODE_RECOVERY)
				sec_set_param_value(__SWITCH_SEL,
						    &default_switchsel);
		}

		/* save __REBOOT_MODE, if CMD is NULL then REBOOT_MODE_NONE will be saved */
		if (sec_set_param_value)
			sec_set_param_value(__REBOOT_MODE, &mode);
	}
	if (sec_get_param_value) {
		sec_get_param_value(__REBOOT_MODE, &temp_mode);
		printk(KERN_INFO "%s: __REBOOT_MODE: 0x%x\n",
			__func__, temp_mode);
		sec_get_param_value(__SWITCH_SEL, &temp_mode);
		printk(KERN_INFO "%s: __SWITCH_SEL: 0x%x\n",
			__func__, temp_mode);
	}
	
	return NOTIFY_DONE;
}				/* end fn __sec_common_reboot_call */

static struct notifier_block __sec_common_reboot_notifier = {
	.notifier_call = __sec_common_reboot_call,
};

/*
 * Store a handy board information string which we can use elsewhere like
 * like in panic situation
 */
static char sec_panic_string[256];
static void __init sec_common_set_panic_string(void)
{
	char *cpu_type = "UNKNOWN";

#if defined(CONFIG_ARCH_OMAP3)
	cpu_type = cpu_is_omap34xx() ? "OMAP3430" : "OMAP3630";
#elif defined(CONFIG_ARCH_OMAP4)
	cpu_type = cpu_is_omap443x() ? "OMAP4430" : "OMAP4460";
#elif defined (CONFIG_MACH_SAMSUNG_U9540)
	cpu_type = cpu_is_u9540() ? "U9540" : "Unknown";
#elif defined(CONFIG_MACH_SAMSUNG_UX500)
	cpu_type = cpu_is_u8500() ? "U8500" : "Unknown";
#endif 

#if defined (CONFIG_MACH_SAMSUNG_U9540)
	snprintf(sec_panic_string, ARRAY_SIZE(sec_panic_string),
		"Venus: %02X, cpu %s ES%d",
//		CONFIG_SAMSUNG_BOARD_NAME,
//		CONFIG_SAMSUNG_MODEL_NAME,
		system_rev, cpu_type,
		dbx500_revision());
#elif defined(CONFIG_MACH_SAMSUNG_UX500)
	snprintf(sec_panic_string, ARRAY_SIZE(sec_panic_string),
		"UX500: %02X, cpu %s ES%d",
//		CONFIG_SAMSUNG_BOARD_NAME,
//		CONFIG_SAMSUNG_MODEL_NAME,
		system_rev, cpu_type,
		dbx500_revision());
#else
	snprintf(sec_panic_string, ARRAY_SIZE(sec_panic_string),
		"%s (%s): %02X, cpu %s ES%d.%d",
		CONFIG_SAMSUNG_BOARD_NAME,
		CONFIG_SAMSUNG_MODEL_NAME,
		system_rev, cpu_type,
		(GET_OMAP_REVISION() >> 4) & 0xf,
		GET_OMAP_REVISION() & 0xf);
#endif
	mach_panic_string = sec_panic_string;
}

#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)
static const char * const omap_types[] = {
	[OMAP2_DEVICE_TYPE_TEST]	= "TST",
	[OMAP2_DEVICE_TYPE_EMU]		= "EMU",
	[OMAP2_DEVICE_TYPE_SEC]		= "HS",
	[OMAP2_DEVICE_TYPE_GP]		= "GP",
	[OMAP2_DEVICE_TYPE_BAD]		= "BAD"
};
#endif
static ssize_t sec_common_soc_family_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)
	return sprintf(buf, "OMAP%04x\n", GET_OMAP_TYPE);
#elif defined (CONFIG_MACH_SAMSUNG_U9540)
	return sprintf(buf, "STE U9540");
#elif defined(CONFIG_MACH_SAMSUNG_UX500)
	return sprintf(buf, "STE U8500");
#endif
}

static ssize_t sec_common_soc_revision_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)
	return sprintf(buf, "ES%d.%d\n",
		       (GET_OMAP_REVISION() >> 4) & 0x0F,
		       (GET_OMAP_REVISION()) & 0xF);
#elif defined (CONFIG_MACH_SAMSUNG_U9540)|| defined(CONFIG_MACH_SAMSUNG_UX500)
return sprintf(buf, "ES%d\n", dbx500_revision());
#endif 
}

static ssize_t sec_common_soc_die_id_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)
	struct omap_die_id oid;

	omap_get_die_id(&oid);

	return sprintf(buf, "%08X-%08X-%08X-%08X\n",
		       oid.id_3, oid.id_2, oid.id_1, oid.id_0);
#elif defined (CONFIG_MACH_SAMSUNG_U9540)|| defined(CONFIG_MACH_SAMSUNG_UX500)
	return sprintf(buf, "Unknown\n");
#endif
}

static ssize_t sec_common_soc_prod_id_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)
	struct omap_die_id oid;

	omap_get_production_id(&oid);

	return sprintf(buf, "%08X-%08X\n", oid.id_1, oid.id_0);
#elif defined (CONFIG_MACH_SAMSUNG_U9540)|| defined(CONFIG_MACH_SAMSUNG_UX500)
	return sprintf(buf, "Unknown\n");
#endif
}

static ssize_t sec_common_soc_type_show(struct kobject *kobj,
					struct kobj_attribute *attr,
					char *buf)
{
#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)
	return sprintf(buf, "%s\n", omap_types[omap_type()]);
#elif defined (CONFIG_MACH_SAMSUNG_U9540)
	return sprintf(buf, "STE U9540\n");
#elif defined(CONFIG_MACH_SAMSUNG_UX500)
	return sprintf(buf, "STE U8500");
#endif
}

#define SEC_COMMON_ATTR_RO(_type, _name)				\
	struct kobj_attribute sec_common_##_type##_prop_attr_##_name =	\
		__ATTR(_name, S_IRUGO,					\
		       sec_common_##_type##_##_name##_show, NULL)

static SEC_COMMON_ATTR_RO(soc, family);
static SEC_COMMON_ATTR_RO(soc, revision);
static SEC_COMMON_ATTR_RO(soc, type);
static SEC_COMMON_ATTR_RO(soc, die_id);
static SEC_COMMON_ATTR_RO(soc, prod_id);

static struct attribute *sec_common_soc_prop_attrs[] = {
	&sec_common_soc_prop_attr_family.attr,
	&sec_common_soc_prop_attr_revision.attr,
	&sec_common_soc_prop_attr_type.attr,
	&sec_common_soc_prop_attr_die_id.attr,
	&sec_common_soc_prop_attr_prod_id.attr,
	NULL,
};

static struct attribute_group sec_common_soc_prop_attr_group = {
	.attrs = sec_common_soc_prop_attrs,
};

static ssize_t sec_common_board_revision_show(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      char *buf)
{
	char *machine_name = *(char **)kallsyms_lookup_name("machine_name");

	return sprintf(buf, "%s Samsung board (0x%02X)\n",
		       machine_name, system_rev);
}

static SEC_COMMON_ATTR_RO(board, revision);

static struct attribute *sec_common_board_prop_attrs[] = {
	&sec_common_board_prop_attr_revision.attr,
	NULL,
};

static struct attribute_group sec_common_board_prop_attr_group = {
	.attrs = sec_common_board_prop_attrs,
};

static void __init sec_common_create_board_props(void)
{
	struct kobject *board_props_kobj;
	struct kobject *soc_kobj;
	int ret = 0;

	board_props_kobj = kobject_create_and_add("board_properties", NULL);
	if (!board_props_kobj)
		goto err_board_obj;

	soc_kobj = kobject_create_and_add("soc", board_props_kobj);
	if (!soc_kobj)
		goto err_soc_obj;

	ret = sysfs_create_group(board_props_kobj,
				 &sec_common_board_prop_attr_group);
	if (ret)
		goto err_board_sysfs_create;

	ret = sysfs_create_group(soc_kobj, &sec_common_soc_prop_attr_group);
	if (ret)
		goto err_soc_sysfs_create;

	return;

err_soc_sysfs_create:
	sysfs_remove_group(board_props_kobj,
			   &sec_common_board_prop_attr_group);
err_board_sysfs_create:
	kobject_put(soc_kobj);
err_soc_obj:
	kobject_put(board_props_kobj);
err_board_obj:
	if (!board_props_kobj || !soc_kobj || ret)
		pr_err("failed to create board_properties\n");
}

int __init sec_common_init_early(void)
{
	sec_common_set_panic_string();
	return 0;
}				/* end fn sec_common_init_early */

static DEVICE_ATTR(checksum_pass, S_IRUGO, checksum_pass_show, NULL);
static DEVICE_ATTR(checksum_done, S_IRUGO, checksum_done_show, NULL);

int __init sec_common_init(void)
{
	sec_class = class_create(THIS_MODULE, "sec");
	if (IS_ERR(sec_class))
		pr_err("Class(sec) Creating Fail!!!\n");

	camera_class = class_create(THIS_MODULE, "camera");
	if (IS_ERR(camera_class))
		pr_err("Class(camera) Creating Fail!!!\n");

	sec_checksum = device_create(sec_class, NULL, 0, NULL, "sec_checksum");
	if (IS_ERR(sec_checksum))
		printk(KERN_ERR "Failed to create device(sec_checksum)!\n");
	if (device_create_file(sec_checksum, &dev_attr_checksum_pass) < 0)
		printk(KERN_ERR "%s device_create_file fail dev_attr_checksum_pass\n", __func__);
	if (device_create_file(sec_checksum, &dev_attr_checksum_done) < 0)
		printk(KERN_ERR "%s device_create_file fail dev_attr_checksum_done\n", __func__);

	sec_common_create_board_props();
#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)
	for (i = 0; i < ARRAY_SIZE(hwrev_gpio); i++) {
		gpio_pin = omap_muxtbl_get_gpio_by_name(hwrev_gpio[i]);
		if (likely(gpio_pin != -EINVAL))
			gpio_request(gpio_pin, hwrev_gpio[i]);
	}
#endif

	return 0;
}				/* end fn sec_common_init */

int __init sec_common_init_post(void)
{
	register_reboot_notifier(&__sec_common_reboot_notifier);
	return 0;
}		/* end fn sec_common_init_post */

struct sec_reboot_mode {
	char *cmd;
	char mode;
};

static __inline char __sec_common_convert_reboot_mode(char mode,
						      const char *cmd)
{
	char new_mode = mode;
	struct sec_reboot_mode mode_tbl[] = {
		{"arm11_fota", 'f'},
		{"arm9_fota", 'f'},
		{"recovery", 'r'},
		{"download", 'd'},
		{"cp_crash", 'C'},
		{"Checkin scheduled forced", 'c'} /* Note - c means REBOOTMODE_NORMAL */
	};
	size_t i, n;
#ifdef CONFIG_SAMSUNG_KERNEL_DEBUG
	if (mode == 'L' || mode == 'U' || mode == 'K') {
		new_mode = mode;
		goto __return;
	}
#endif /* CONFIG_SAMSUNG_KERNEL_DEBUG */
	if (cmd == NULL)
		goto __return;
	n = ARRAY_SIZE(mode_tbl);
	for (i = 0; i < n; i++) {
		if (!strcmp(cmd, mode_tbl[i].cmd)) {
			new_mode = mode_tbl[i].mode;
			goto __return;
		} else if(!strncmp(cmd, "sud", 3)) {
			new_mode = 's';
			goto __return;
		}
	}

__return:
	return new_mode;
}

#define SEC_REBOOT_MODE_ADDR		0
#define SEC_REBOOT_FLAG_ADDR		0

unsigned short sec_common_update_reboot_reason(char mode, const char *cmd)
{
	unsigned short scpad = 0;
	const u32 scpad_addr = SEC_REBOOT_MODE_ADDR;
	unsigned short reason = REBOOTMODE_NORMAL;
	unsigned short ret;

#if 0
	/* for the compatibility with LSI chip-set based products */

	printk(KERN_INFO "sec_common_update_reboot_reason: scpad_addr: 0x%x\n",
			scpad_addr);
	if (cmd)
		printk(KERN_INFO "sec_common_update_reboot_reason: mode= %c, cmd= %s\n",
				mode, cmd);
	mode = __sec_common_convert_reboot_mode(mode, cmd);
	printk(KERN_INFO "mode: %c\n", mode);
#else
	mode = __sec_common_convert_reboot_mode(mode, cmd);
#endif

	switch (mode) {
	case 'r':		/* reboot mode = recovery */
		reason = REBOOTMODE_RECOVERY;
		break;
	case 'f':		/* reboot mode = fota */
		reason = REBOOTMODE_FOTA;
		break;
	case 't':		/* reboot mode = shutdown with TA */
	case 'u':		/* reboot mode = shutdown with USB */
	case 'j':		/* reboot mode = shutdown with JIG */
		reason = REBOOTMODE_SHUTDOWN;
		break;
	case 's':		/* reboot mode = download */
	case 'd':		/* reboot mode = download */
		reason = REBOOTMODE_DOWNLOAD;
		break;
	default:		/* reboot mode = normal */
		reason = REBOOTMODE_NORMAL;
		break;
	}

#if defined(CONFIG_ARCH_OMAP3) || defined(CONFIG_ARCH_OMAP4)
		omap_writel(scpad | reason, scpad_addr);
		omap_writel(*(u32 *)rebootflag, SEC_REBOOT_FLAG_ADDR);
#endif
	ret = (scpad | reason);
	return ret;
} /* sec_common_update_reboot_reason */
