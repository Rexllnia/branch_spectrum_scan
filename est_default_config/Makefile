include $(TOPDIR)/rules.mk
include $(TOPDIR)/.config

PKG_NAME:=rg_est_default_config
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk


define Package/$(PKG_NAME)
	SUBMENU:=Utilities
	CATEGORY:=Ruijie Properties
	TITLE:=Ruijie Bridge check whether the default configuration is set
	DEPENDS:= +libjson-c +libuci +libubox +was\
			$(if $(CONFIG_RG_FRAME_C_CMD),+rg_unified_framework)
endef

define Package/$(PKG_NAME)/description
	Bridge check whether the default configuration is set
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)  CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)"
endef

export DefaultConfig_MODULE_SO := libDefaultConfig.so

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/ufplugins
	$(CP) $(PKG_BUILD_DIR)/plugin/$(DefaultConfig_MODULE_SO)* $(1)/usr/lib/ufplugins/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib/ufplugins
	$(CP) $(PKG_BUILD_DIR)/plugin/$(DefaultConfig_MODULE_SO)* $(1)/usr/lib/ufplugins
endef

$(eval $(call BuildPackage,$(PKG_NAME)))