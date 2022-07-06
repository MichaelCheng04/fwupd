/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <glib/gi18n.h>
#include <json-glib/json-glib.h>

#include "fwupd-security-attr-private.h"

#include "fu-security-attr.h"
#include "fu-security-attrs-private.h"

gchar *
fu_security_attr_get_name(FwupdSecurityAttr *attr)
{
	const gchar *appstream_id = fwupd_security_attr_get_appstream_id(attr);
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_BIOSWE) == 0) {
		/* TRANSLATORS: Title: SPI refers to the flash chip in the computer */
		return g_strdup(_("SPI write"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_BLE) == 0) {
		/* TRANSLATORS: Title: SPI refers to the flash chip in the computer */
		return g_strdup(_("SPI lock"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_SMM_BWP) == 0) {
		/* TRANSLATORS: Title: SPI refers to the flash chip in the computer */
		return g_strdup(_("SPI BIOS region"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_DESCRIPTOR) == 0) {
		/* TRANSLATORS: Title: SPI refers to the flash chip in the computer */
		return g_strdup(_("SPI BIOS Descriptor"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PREBOOT_DMA_PROTECTION) == 0) {
		/* TRANSLATORS: Title: DMA as in https://en.wikipedia.org/wiki/DMA_attack  */
		return g_strdup(_("Pre-boot DMA protection"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ENABLED) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel */
		return g_strdup(_("Intel BootGuard"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_VERIFIED) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel,
		 * verified boot refers to the way the boot process is verified */
		return g_strdup(_("Intel BootGuard verified boot"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ACM) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel,
		 * ACM means to verify the integrity of Initial Boot Block */
		return g_strdup(_("Intel BootGuard ACM protected"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_POLICY) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel,
		 * error policy is what to do on failure */
		return g_strdup(_("Intel BootGuard error policy"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_OTP) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel,
		 * OTP = one time programmable */
		return g_strdup(_("Intel BootGuard OTP fuse"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ENABLED) == 0) {
		/* TRANSLATORS: Title: CET = Control-flow Enforcement Technology,
		 * enabled means supported by the processor */
		return g_strdup(_("Intel CET Enabled"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ACTIVE) == 0) {
		/* TRANSLATORS: Title: CET = Control-flow Enforcement Technology,
		 * active means being used by the OS */
		return g_strdup(_("Intel CET Active"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_SMAP) == 0) {
		/* TRANSLATORS: Title: SMAP = Supervisor Mode Access Prevention */
		return g_strdup(_("Intel SMAP"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_ENCRYPTED_RAM) == 0) {
		/* TRANSLATORS: Title: Memory contents are encrypted, e.g. Intel TME */
		return g_strdup(_("Encrypted RAM"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_IOMMU) == 0) {
		/* TRANSLATORS: Title:
		 * https://en.wikipedia.org/wiki/Input%E2%80%93output_memory_management_unit */
		return g_strdup(_("IOMMU"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_LOCKDOWN) == 0) {
		/* TRANSLATORS: Title: lockdown is a security mode of the kernel */
		return g_strdup(_("Linux kernel lockdown"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_TAINTED) == 0) {
		/* TRANSLATORS: Title: if it's tainted or not */
		return g_strdup(_("Linux kernel"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_SWAP) == 0) {
		/* TRANSLATORS: Title: swap space or swap partition */
		return g_strdup(_("Linux swap"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_RAM) == 0) {
		/* TRANSLATORS: Title: sleep state */
		return g_strdup(_("Suspend-to-ram"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_IDLE) == 0) {
		/* TRANSLATORS: Title: a better sleep state */
		return g_strdup(_("Suspend-to-idle"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_UEFI_PK) == 0) {
		/* TRANSLATORS: Title: PK is the 'platform key' for the machine */
		return g_strdup(_("UEFI platform key"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_UEFI_SECUREBOOT) == 0) {
		/* TRANSLATORS: Title: SB is a way of locking down UEFI */
		return g_strdup(_("UEFI secure boot"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_EMPTY_PCR) == 0) {
		/* TRANSLATORS: Title: PCRs (Platform Configuration Registers) shouldn't be empty */
		return g_strdup(_("TPM empty PCRs"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_RECONSTRUCTION_PCR0) == 0) {
		/* TRANSLATORS: Title: the PCR is rebuilt from the TPM event log */
		return g_strdup(_("TPM PCR0 reconstruction"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_VERSION_20) == 0) {
		/* TRANSLATORS: Title: TPM = Trusted Platform Module */
		return g_strdup(_("TPM v2.0"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_MANUFACTURING_MODE) == 0) {
		const gchar *kind = fwupd_security_attr_get_metadata(attr, "kind");
		if (kind != NULL) {
			/* TRANSLATORS: Title: %s is ME kind, e.g. CSME/TXT */
			return g_strdup_printf(_("%s manufacturing mode"), kind);
		}
		/* TRANSLATORS: Title: MEI = Intel Management Engine */
		return g_strdup(_("MEI manufacturing mode"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_OVERRIDE_STRAP) == 0) {
		const gchar *kind = fwupd_security_attr_get_metadata(attr, "kind");
		if (kind != NULL) {
			/* TRANSLATORS: Title: %s is ME kind, e.g. CSME/TXT */
			return g_strdup_printf(_("%s override"), kind);
		}
		/* TRANSLATORS: Title: MEI = Intel Management Engine, and the
		 * "override" is the physical PIN that can be driven to
		 * logic high -- luckily it is probably not accessible to
		 * end users on consumer boards */
		return g_strdup(_("MEI override"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_VERSION) == 0) {
		/* TRANSLATORS: Title: MEI = Intel Management Engine */
		const gchar *kind = fwupd_security_attr_get_metadata(attr, "kind");
		const gchar *version = fwupd_security_attr_get_metadata(attr, "version");
		if (kind != NULL && version != NULL) {
			/* TRANSLATORS: Title: %1 is ME kind, e.g. CSME/TXT, %2 is a version number
			 */
			return g_strdup_printf(_("%s v%s"), kind, version);
		}
		if (kind != NULL) {
			/* TRANSLATORS: Title: %s is ME kind, e.g. CSME/TXT */
			return g_strdup_printf(_("%s version"), kind);
		}
		return g_strdup(_("MEI version"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_UPDATES) == 0) {
		/* TRANSLATORS: Title: if firmware updates are available */
		return g_strdup(_("Firmware updates"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_ATTESTATION) == 0) {
		/* TRANSLATORS: Title: if we can verify the firmware checksums */
		return g_strdup(_("Firmware attestation"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_PLUGINS) == 0) {
		/* TRANSLATORS: Title: if the fwupd plugins are all present and correct */
		return g_strdup(_("fwupd plugins"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_ENABLED) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_LOCKED) == 0) {
		/* TRANSLATORS: Title: Allows debugging of parts using proprietary hardware */
		return g_strdup(_("Platform Debugging"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUPPORTED_CPU) == 0) {
		/* TRANSLATORS: Title: if fwupd supports HSI on this chip */
		return g_strdup(_("Supported CPU"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_ROLLBACK_PROTECTION) == 0) {
		/* TRANSLATORS: Title: if firmware enforces rollback protection */
		return g_strdup(_("Rollback protection"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_SPI_REPLAY_PROTECTION) == 0) {
		/* TRANSLATORS: Title: if hardware enforces control of SPI replays */
		return g_strdup(_("SPI replay protection"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_SPI_WRITE_PROTECTION) == 0) {
		/* TRANSLATORS: Title: if hardware enforces control of SPI writes */
		return g_strdup(_("SPI write protection"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_FUSED) == 0) {
		/* TRANSLATORS: Title: if the part has been fused */
		return g_strdup(_("Fused platform"));
	}

	/* we should not get here */
	return g_strdup(fwupd_security_attr_get_name(attr));
}

const gchar *
fu_security_attr_get_title(FwupdSecurityAttr *attr)
{
	const gchar *appstream_id = fwupd_security_attr_get_appstream_id(attr);
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_BIOSWE) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_BLE) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_SMM_BWP) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_DESCRIPTOR) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_UPDATES) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_ROLLBACK_PROTECTION) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_SPI_REPLAY_PROTECTION) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_SPI_WRITE_PROTECTION) == 0) {
		/* TRANSLATORS: Title: this refers to the flash chip in the computer */
		return _("System Firmware");
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PREBOOT_DMA_PROTECTION) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_IOMMU) == 0) {
		/* TRANSLATORS: Title: device as in peripherals  */
		return _("Device Protection");
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ENABLED) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_VERIFIED) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ACM) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_POLICY) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_OTP) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_UEFI_PK) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_UEFI_SECUREBOOT) == 0) {
		/* TRANSLATORS: Title: the secure boot chain */
		return _("Secure Boot");
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ENABLED) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ACTIVE) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_SMAP) == 0) {
		/* TRANSLATORS: Title: in this case means the main CPU */
		return _("Processor Protection");
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_ENCRYPTED_RAM) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_SWAP) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_RAM) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_IDLE) == 0) {
		/* TRANSLATORS: Title: memory as in system DRAM */
		return _("Memory Protection");
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_LOCKDOWN) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_TAINTED) == 0) {
		/* TRANSLATORS: Title: your Linux OS, not the nut */
		return _("Kernel Protection");
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_EMPTY_PCR) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_RECONSTRUCTION_PCR0) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_VERSION_20) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_ATTESTATION) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_PLUGINS) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUPPORTED_CPU) == 0) {
		/* TRANSLATORS: Title: attestation means verifying your system state */
		return _("System Attestation");
	}

	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_MANUFACTURING_MODE) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_OVERRIDE_STRAP) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_VERSION) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_ENABLED) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_LOCKED) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_FUSED) == 0) {
		/* TRANSLATORS: Title: as in your entire computer */
		return _("System Protection");
	}
	return NULL;
}

/* one line saying the problem, then one line saying why -- or how to fix the problem */
gchar *
fu_security_attr_get_description(FwupdSecurityAttr *attr)
{
	const gchar *appstream_id = fwupd_security_attr_get_appstream_id(attr);
	g_autoptr(GPtrArray) strs = g_ptr_array_new();
	gboolean contact_hw_vendor = FALSE;
	gboolean check_bios_settings = FALSE;

	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_BIOSWE) == 0 &&
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_SPI_WRITE_PROTECTION) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer success message (unlikely to see) */
			    _("The system firmware is locked and not writable at runtime."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The system firmware is unlocked and writable by any "
					  "privileged user."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_BLE) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			/* TRANSLATORS: longer success message (unlikely to see) */
			g_ptr_array_add(strs, _("The system firmware cannot be easily unlocked."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The system firmware can be unlocked and written by any "
					  "privileged user."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_SMM_BWP) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			/* TRANSLATORS: longer success message (unlikely to see) */
			g_ptr_array_add(strs, _("The system firmware cannot be unlocked."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The system firmware could be unlocked and written by "
					  "any privileged user."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_DESCRIPTOR) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("Critical areas of the system firmware are protected."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("Critical areas of the system firmware could be changed "
					  "by any privileged user."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PREBOOT_DMA_PROTECTION) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("System memory is protected from malicious devices "
					  "before starting the OS."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("System memory is not protected from malicious devices "
					  "before starting the OS."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ENABLED) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_VERIFIED) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("System firmware is being verified by the processor at "
					  "system start."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("System firmware is not being verified by the processor "
					  "at system start."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ACM) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("System firmware is being completely verified by the "
					  "processor at system start."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("System firmware is not being completely verified by the "
					  "processor at system start."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_POLICY) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("Critical failures of system firmware verification cause "
					  "system startup to stop."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("Critical failures of system firmware verification can "
					  "be ignored by the user."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_OTP) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("System firmware verification cannot be disabled."));
		} else {
			/* TRANSLATORS: longer failure message */
			g_ptr_array_add(strs, _("System firmware verification has been disabled."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ENABLED) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("The processor could detect and ignore more attack "
					  "attempts from malicious software."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The processor cannot detect and ignore more attack "
					  "attempts from malicious software."));
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ACTIVE) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("The processor will detect and ignore targeted attack "
					  "attempts from malicious software."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The processor will not detect and ignore targeted "
					  "attack attempts from malicious software."));
			check_bios_settings = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_SMAP) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("The processor can detect and ignore some attacks from "
					  "malicious software."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The processor cannot detect and ignore some attacks "
					  "from malicious software."));
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_ENCRYPTED_RAM) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("Memory is being encrypted and the contents cannot be "
					  "recovered if removed by an attacker."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("Memory is not encrypted and the contents may be "
					  "recovered if removed by an attacker."));
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_IOMMU) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer success message (unlikely to see) */
			    _("Malicious peripherals cannot write to main system memory."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("Some malicious peripherals could potentially write to "
					  "main system memory."));
			check_bios_settings = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_LOCKDOWN) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("Your operating system is protected against malicious "
					  "software writing directly to the hardware."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("Your operating system is not protected against "
					  "malicious software writing directly to the hardware."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_TAINTED) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			/* TRANSLATORS: longer success message */
			g_ptr_array_add(strs,
					_("There is no software has been added to your operating "
					  "system that would affect platform security."));
		} else {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer failure message */
			    _("Unverified software has been added to your operating system."));
			g_ptr_array_add(
			    strs,
			    _("This can be the result of adding unsigned drivers, and means that "
			      "some security features may no longer function."));
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_SWAP) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("Temporary files saved to disk are encrypted and cannot "
					  "be read by an attacker."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("Temporary files saved to disk are not encrypted and "
					  "could be read by an attacker."));
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_RAM) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_IDLE) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("The system sleep mode is set correctly so that files "
					  "are not readable."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The system sleep mode could allow an attacker to remove "
					  "system memory and read the content."));
			check_bios_settings = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_UEFI_PK) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("Your system startup is being verified correctly."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The key used for secure system startup is not valid."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_UEFI_SECUREBOOT) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			/* TRANSLATORS: longer success message */
			g_ptr_array_add(
			    strs,
			    _("Your system startup is being protected by Secure Boot."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("System startup is not being protected by Secure Boot "
					  "which would allow an attacker to install software run "
					  "before your operating system starts."));
			check_bios_settings = TRUE;
		}
	}

	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_EMPTY_PCR) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			/* TRANSLATORS: longer success message (unlikely to see) */
			g_ptr_array_add(strs, _("System attestation values have been set."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("System attestation values have not been set and "
					  "firmware protection may be incomplete."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_RECONSTRUCTION_PCR0) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer success message (unlikely to see) */
			    _("System firmware and startup measurements have been verified."));
		} else {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer failure message */
			    _("System firmware and startup measurements could not be verified and "
			      "so firmware protection may be incomplete."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_VERSION_20) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("System firmware and startup measurements are being "
					  "collected for verification."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("System firmware and startup measurements cannot be "
					  "being collected for verification."));
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_MANUFACTURING_MODE) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_FUSED) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("The system has been correctly configured when assembed "
					  "by the vendor and firmware is being protected."));
		} else {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer failure message */
			    _("The system has not been correctly configured when assembed by the "
			      "vendor, which may allow an attacker to replace system firmware."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_OVERRIDE_STRAP) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer success message (unlikely to see) */
			    _("The mainboard has not disabled system firmware protection."));
		} else {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer failure message */
			    _("The mainboard has disabled system firmware protection which may "
			      "allow an attacker to replace system firmware."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_VERSION) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer success message (unlikely to see) */
			    _("The management processor is not critically out-of-date."));
		} else {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer failure message */
			    _("The management processor is critically out-of-date and it may be "
			      "possible for a remote attacker to modify the system firmware even "
			      "when the computer is powered off."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_UPDATES) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer success message (unlikely to see) */
			    _("System firmware updates are available for this system."));
		} else {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer failure message */
			    _("System firmware updates are not available for this system."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_ATTESTATION) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("System firmware verification measurements have been "
					  "provided by the vendor for this system."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("System firmware verification measurements have not been "
					  "provided by the vendor for this system."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_PLUGINS) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer success message (unlikely to see) */
			    _("The fwupd software is set up correctly and all plugins are valid."));
		} else {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer failure message */
			    _("The fwupd software has not been set up correctly or some "
			      "plugins are invalid."));
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_ENABLED) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			/* TRANSLATORS: longer success message (unlikely to see) */
			g_ptr_array_add(strs, _("Low-level hardware debugging is not enabled."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("Low-level hardware debugging has been enabled for this "
					  "system and the firmware and OS are not secure."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_LOCKED) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer success message (unlikely to see) */
			    _("Low-level hardware debugging has been locked to prevent misuse."));
		} else {
			g_ptr_array_add(
			    strs,
			    /* TRANSLATORS: longer failure message */
			    _("Low-level hardware debugging can been enabled for this system and "
			      "if enabled, the firmware and OS would not be secure."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUPPORTED_CPU) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("This system can be tested for firmware security."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("This system cannot be tested for firmware security as "
					  "it does not have a supported processor or mainboard."));
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_ROLLBACK_PROTECTION) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("The system firmware cannot be downgraded to an older "
					  "legitimate version with potential security problems."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The system firmware can be downgraded to an older "
					  "legitimate version with potential security problems."));
			contact_hw_vendor = TRUE;
		}
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_AMD_SPI_REPLAY_PROTECTION) == 0) {
		if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer success message (unlikely to see) */
					_("The system firmware cannot be tricked into repeating "
					  "privileged actions by a malicious user."));
		} else {
			g_ptr_array_add(strs,
					/* TRANSLATORS: longer failure message */
					_("The system firmware could be tricked into repeating "
					  "privileged actions by a malicious user."));
			contact_hw_vendor = TRUE;
		}
	}

	/* any postfix */
	if (contact_hw_vendor) {
		g_ptr_array_add(strs,
				/* TRANSLATORS: do not translate $HostVendor$ */
				_("Ensure you have installed all available firmware updates and if "
				  "still not fixed then contact $HostVendor$."));
	}
	if (check_bios_settings) {
		g_ptr_array_add(
		    strs,
		    /* TRANSLATORS: it's frustrating we can't give better instructions */
		    _("There may be a setting to control this in your system firmware "
		      "setup, which can be reached before your OS has booted."));
	}

	/* convert to a single line */
	g_ptr_array_add(strs, NULL);
	return g_strjoinv(" ", (gchar **)strs->pdata);
}

const gchar *
fu_security_attr_result_to_string(FwupdSecurityAttrResult result)
{
	if (result == FWUPD_SECURITY_ATTR_RESULT_VALID) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Valid");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_VALID) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Invalid");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_ENABLED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Enabled");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_ENABLED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Disabled");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_LOCKED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Locked");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_LOCKED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Unlocked");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_ENCRYPTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Encrypted");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_ENCRYPTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Unencrypted");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_TAINTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Tainted");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_TAINTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Untainted");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_FOUND) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Found");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_FOUND) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Not found");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_SUPPORTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Supported");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_SUPPORTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Not supported");
	}
	return NULL;
}

const gchar *
fu_security_attr_get_result(FwupdSecurityAttr *attr)
{
	const gchar *tmp;

	/* common case */
	tmp = fu_security_attr_result_to_string(fwupd_security_attr_get_result(attr));
	if (tmp != NULL)
		return tmp;

	/* fallback */
	if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("OK");
	}

	/* TRANSLATORS: Suffix: the fallback HSI result */
	return _("Failed");
}

/**
 * fu_security_attrs_to_json_string：
 * Convert security attribute to JSON string.
 * @attrs: a pointer for a FuSecurityAttrs data structure.
 * @error: return location for an error
 *
 * fu_security_attrs_to_json_string() converts FuSecurityAttrs and return the
 * string pointer. The converted JSON format is shown as follows:
 * {
 *     "SecurityAttributes": [
 *         {
 *              "name": "aaa",
 *              "value": "bbb"
 *         }
 *     ]
 *  }
 *
 * Returns: A string and NULL on fail.
 *
 * Since: 1.7.0
 *
 */
gchar *
fu_security_attrs_to_json_string(FuSecurityAttrs *attrs, GError **error)
{
	g_autofree gchar *data = NULL;
	g_autoptr(JsonGenerator) json_generator = NULL;
	g_autoptr(JsonBuilder) builder = json_builder_new();
	g_autoptr(JsonNode) json_root = NULL;
	fu_security_attrs_to_json(attrs, builder);
	json_root = json_builder_get_root(builder);
	json_generator = json_generator_new();
	json_generator_set_pretty(json_generator, TRUE);
	json_generator_set_root(json_generator, json_root);
	data = json_generator_to_data(json_generator, NULL);
	if (data == NULL) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "Failed to convert security attribute to json.");
		return NULL;
	}
	return g_steal_pointer(&data);
}

void
fu_security_attrs_to_json(FuSecurityAttrs *attrs, JsonBuilder *builder)
{
	g_autoptr(GPtrArray) items = NULL;

	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "SecurityAttributes");
	json_builder_begin_array(builder);
	items = fu_security_attrs_get_all(attrs);
	for (guint i = 0; i < items->len; i++) {
		FwupdSecurityAttr *attr = g_ptr_array_index(items, i);
		guint64 created = fwupd_security_attr_get_created(attr);
		json_builder_begin_object(builder);
		fwupd_security_attr_set_created(attr, 0);
		fwupd_security_attr_to_json(attr, builder);
		fwupd_security_attr_set_created(attr, created);
		json_builder_end_object(builder);
	}
	json_builder_end_array(builder);
	json_builder_end_object(builder);
}

gboolean
fu_security_attrs_from_json(FuSecurityAttrs *attrs, JsonNode *json_node, GError **error)
{
	JsonArray *array;
	JsonObject *obj;

	/* sanity check */
	if (!JSON_NODE_HOLDS_OBJECT(json_node)) {
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "not JSON object");
		return FALSE;
	}
	obj = json_node_get_object(json_node);

	/* this has to exist */
	if (!json_object_has_member(obj, "SecurityAttributes")) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "no SecurityAttributes property in object");
		return FALSE;
	}
	array = json_object_get_array_member(obj, "SecurityAttributes");
	for (guint i = 0; i < json_array_get_length(array); i++) {
		JsonNode *node_tmp = json_array_get_element(array, i);
		g_autoptr(FwupdSecurityAttr) attr = fwupd_security_attr_new(NULL);
		if (!fwupd_security_attr_from_json(attr, node_tmp, error))
			return FALSE;
		fu_security_attrs_append(attrs, attr);
	}

	/* success */
	return TRUE;
}

/**
 * fu_security_attrs_compare：
 * @attrs1: a #FuSecurityAttrs
 * @attrs2: another #FuSecurityAttrs, perhaps newer in some way
 *
 * Compares the two objects, returning the differences.
 *
 * If the two sets of attrs are considered the same then an empty array is returned.
 * Only the AppStream ID results are compared, extra metadata is ignored.
 *
 * Returns: (element-type FwupdSecurityAttr) (transfer container): differences
 */
GPtrArray *
fu_security_attrs_compare(FuSecurityAttrs *attrs1, FuSecurityAttrs *attrs2)
{
	g_autoptr(GHashTable) hash1 = g_hash_table_new(g_str_hash, g_str_equal);
	g_autoptr(GHashTable) hash2 = g_hash_table_new(g_str_hash, g_str_equal);
	g_autoptr(GPtrArray) array1 = fu_security_attrs_get_all(attrs1);
	g_autoptr(GPtrArray) array2 = fu_security_attrs_get_all(attrs2);
	g_autoptr(GPtrArray) results =
	    g_ptr_array_new_with_free_func((GDestroyNotify)g_object_unref);

	/* create hash tables of appstream-id -> FwupdSecurityAttr */
	for (guint i = 0; i < array1->len; i++) {
		FwupdSecurityAttr *attr1 = g_ptr_array_index(array1, i);
		g_hash_table_insert(hash1,
				    (gpointer)fwupd_security_attr_get_appstream_id(attr1),
				    (gpointer)attr1);
	}
	for (guint i = 0; i < array2->len; i++) {
		FwupdSecurityAttr *attr2 = g_ptr_array_index(array2, i);
		g_hash_table_insert(hash2,
				    (gpointer)fwupd_security_attr_get_appstream_id(attr2),
				    (gpointer)attr2);
	}

	/* present in attrs2, not present in attrs1 */
	for (guint i = 0; i < array2->len; i++) {
		FwupdSecurityAttr *attr1;
		FwupdSecurityAttr *attr2 = g_ptr_array_index(array2, i);
		attr1 = g_hash_table_lookup(hash1, fwupd_security_attr_get_appstream_id(attr2));
		if (attr1 == NULL) {
			g_autoptr(FwupdSecurityAttr) attr = fwupd_security_attr_copy(attr2);
			g_ptr_array_add(results, g_steal_pointer(&attr));
			continue;
		}
	}

	/* present in attrs1, not present in attrs2 */
	for (guint i = 0; i < array1->len; i++) {
		FwupdSecurityAttr *attr1 = g_ptr_array_index(array1, i);
		FwupdSecurityAttr *attr2;
		attr2 = g_hash_table_lookup(hash2, fwupd_security_attr_get_appstream_id(attr1));
		if (attr2 == NULL) {
			g_autoptr(FwupdSecurityAttr) attr = fwupd_security_attr_copy(attr1);
			fwupd_security_attr_set_result(attr, FWUPD_SECURITY_ATTR_RESULT_UNKNOWN);
			fwupd_security_attr_set_result_fallback(
			    attr, /* flip these around */
			    fwupd_security_attr_get_result(attr1));
			g_ptr_array_add(results, g_steal_pointer(&attr));
			continue;
		}
	}

	/* find any attributes that differ */
	for (guint i = 0; i < array2->len; i++) {
		FwupdSecurityAttr *attr1;
		FwupdSecurityAttr *attr2 = g_ptr_array_index(array2, i);
		attr1 = g_hash_table_lookup(hash1, fwupd_security_attr_get_appstream_id(attr2));
		if (attr1 == NULL)
			continue;

		/* result of specific attr differed */
		if (fwupd_security_attr_get_result(attr1) !=
		    fwupd_security_attr_get_result(attr2)) {
			g_autoptr(FwupdSecurityAttr) attr = fwupd_security_attr_copy(attr1);
			fwupd_security_attr_set_result(attr, fwupd_security_attr_get_result(attr2));
			fwupd_security_attr_set_result_fallback(
			    attr,
			    fwupd_security_attr_get_result(attr1));
			fwupd_security_attr_set_flags(attr, fwupd_security_attr_get_flags(attr2));
			g_ptr_array_add(results, g_steal_pointer(&attr));
		}
	}

	/* success */
	return g_steal_pointer(&results);
}

/**
 * fu_security_attrs_equal：
 * @attrs1: a #FuSecurityAttrs
 * @attrs2: another #FuSecurityAttrs
 *
 * Tests the objects for equality. Only the AppStream ID results are compared, extra metadata
 * is ignored.
 *
 * Returns: %TRUE if the set of attrs can be considered equal
 */
gboolean
fu_security_attrs_equal(FuSecurityAttrs *attrs1, FuSecurityAttrs *attrs2)
{
	g_autoptr(GPtrArray) compare = fu_security_attrs_compare(attrs1, attrs2);
	return compare->len == 0;
}
