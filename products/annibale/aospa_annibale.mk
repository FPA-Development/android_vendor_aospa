#
# SPDX-FileCopyrightText: Paranoid Android
# SPDX-License-Identifier: Apache-2.0
#

ifeq (aospa_annibale,$(TARGET_PRODUCT))

# Inherit from those products. Most specific first.
$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base_telephony.mk)

# Inherit from the device configuration.
$(call inherit-product, device/xiaomi/annibale/device.mk)

# Inherit from the AOSPA configuration.
$(call inherit-product, vendor/aospa/target/product/aospa-target.mk)

# Inherit from the MiuiCamera setup if present.
$(call inherit-product-if-exists, device/xiaomi/annibale-miuicamera/device.mk)

PRODUCT_BRAND := POCO
PRODUCT_DEVICE := annibale
PRODUCT_MANUFACTURER := Xiaomi
PRODUCT_MODEL := 2510DPC44G
PRODUCT_NAME := aospa_annibale

PRODUCT_SYSTEM_NAME := annibale_global
PRODUCT_SYSTEM_DEVICE := annibale

PRODUCT_BUILD_PROP_OVERRIDES += \
    BuildDesc="annibale-user 16 BP2A.250605.031.A3 OS3.0.301.0.WPKMIXM release-keys" \
    BuildFingerprint=POCO/annibale_global/annibale:16/BP2A.250605.031.A3/OS3.0.301.0.WPKMIXM:user/release-keys \
    DeviceName=$(PRODUCT_SYSTEM_DEVICE) \
    DeviceProduct=$(PRODUCT_SYSTEM_NAME)

PRODUCT_GMS_CLIENTID_BASE := android-xiaomi

# Boot Animation
TARGET_BOOT_ANIMATION_RES := 1080
TARGET_USES_BLUR := true

endif
