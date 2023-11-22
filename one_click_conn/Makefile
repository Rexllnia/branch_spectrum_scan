include $(TOPDIR)/rules.mk
include $(TOPDIR)/.config

PKG_NAME:=rg_one_click_conn
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk


define Package/$(PKG_NAME)
	SUBMENU:=Utilities
	CATEGORY:=Ruijie Properties
	TITLE:=Ruijie Bridge One Click Connect
	DEPENDS:= +libjson-c +libuci +libubox +was +rg_crypto +lib_c\
			$(if $(CONFIG_RG_FRAME_C_CMD),+rg_unified_framework)
endef

define Package/$(PKG_NAME)/description
	Bridge product easy connection function
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	#PKG_BUILD_DIR=/home/huangyongyuan/localbuilder/460g/buildroot/build_dir/target-mipsel_24kec+dsp_uClibc-0.9.33.2/one_cc-1.0.0  CC=mipsel-openwrt-linux-uclibc-gcc CROSS_COMPILE=mipsel-openwrt-linux-uclibc-"
	$(MAKE) -C $(PKG_BUILD_DIR)  CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)"
endef

export ONE_CC_MODULE_SO := libOneClickConn.so

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/ufplugins
	$(CP) $(PKG_BUILD_DIR)/plugin/$(ONE_CC_MODULE_SO)* $(1)/usr/lib/ufplugins/

	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP) $(PKG_BUILD_DIR)/one_click_conn/*.elf $(1)/usr/sbin/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib/ufplugins
	$(CP) $(PKG_BUILD_DIR)/plugin/$(ONE_CC_MODULE_SO)* $(1)/usr/lib/ufplugins
endef

$(eval $(call BuildPackage,$(PKG_NAME)))