# Kernel module rg_wds_beacon

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=rg_wds_beacon
PKG_RELEASE:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/$(PKG_NAME)
	SECTION:=Ruijie wds_beacon
	CATEGORY:=Ruijie Properties
	SUBMENU:=Kernel modules
	TITLE:= Ruijie wds_beacon_test Module
	FILES:=$(PKG_BUILD_DIR)/rg_wds_beacon.ko
	AUTOLOAD:=$(call AutoLoad,20,$(PKG_NAME))
endef

define KernelPackage/$(PKG_NAME)/config
	
config ESTBCN_REGISTER_MT7663_CB_SUPPORT
	bool "support regiser MT7663 callback support"
	depends on PACKAGE_kmod-rg_wds_beacon
	default n
	
config ESTBCN_REGISTER_MT7628_CB_SUPPORT
	bool "support regiser MT7628 callback support"
	depends on PACKAGE_kmod-rg_wds_beacon
	default n
endef
 
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	mkdir -p $(STAGING_DIR)/usr/include
	mkdir -p $(STAGING_DIR)/usr/include/rg_wds
	$(CP) $(PKG_BUILD_DIR)/rg_wds_beacon.h $(STAGING_DIR)/usr/include/rg_wds/
endef

ifdef CONFIG_ESTBCN_REGISTER_MT7663_CB_SUPPORT
	EXTRA_CFLAGS += -DESTBCN_REGISTER_MT7663_CB_SUPPORT
endif

ifdef CONFIG_ESTBCN_REGISTER_MT7628_CB_SUPPORT
	EXTRA_CFLAGS += -DESTBCN_REGISTER_MT7628_CB_SUPPORT
endif

define Build/Compile
	 $(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		PATH="$(TARGET_PATH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
        CFLAGS="$(TARGET_CFLAGS) -I$(EXPORT_HEADER)/"\
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)"\
        modules
endef

$(eval $(call KernelPackage,$(PKG_NAME)))
