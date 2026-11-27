#
# SPDX-FileCopyrightText: Paranoid Android
# SPDX-License-Identifier: Apache-2.0
#

ifeq (aospa_zorn,$(TARGET_PRODUCT))

# Inherit from those products. Most specific first.
$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base_telephony.mk)

# Inherit from the device configuration.
$(call inherit-product, device/xiaomi/zorn/device.mk)

# Inherit from the AOSPA configuration.
$(call inherit-product, vendor/aospa/target/product/aospa-target.mk)

PRODUCT_BRAND := POCO
PRODUCT_DEVICE := zorn
PRODUCT_MANUFACTURER := Xiaomi
PRODUCT_MODEL := 24117RK2CG
PRODUCT_NAME := aospa_zorn

PRODUCT_SYSTEM_NAME := zorn_global
PRODUCT_SYSTEM_DEVICE := zorn

PRODUCT_BUILD_PROP_OVERRIDES += \
    BuildDesc="zorn_global-user 16 BP2A.250605.031.A3 16OS3.1.261022.200509756.QCPEGL.S release-keys" \
    BuildFingerprint=POCO/zorn_global/zorn:16/BP2A.250605.031.A3/16OS3.1.261022.200509756.QCPEGL.S:user/release-keys \
    DeviceName=$(PRODUCT_SYSTEM_DEVICE) \
    DeviceProduct=$(PRODUCT_SYSTEM_NAME)

PRODUCT_GMS_CLIENTID_BASE := android-xiaomi

# Boot Animation
TARGET_BOOT_ANIMATION_RES := 1440
TARGET_USES_BLUR := true

endif
