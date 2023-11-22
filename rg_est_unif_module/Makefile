include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=rg_est_unif_module
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

define Package/$(PKG_NAME)
  SUBMENU:=Utilities
  CATEGORY:=Ruijie Properties
  TITLE:=Ruijie est unif_module
  DEPENDS:= +rg_unified_framework +libjson-c
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -r ./scan_ap $(PKG_BUILD_DIR)/
	$(CP) -r ./scan_wds_ap $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/scan_ap/ CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)"
	$(MAKE) -C $(PKG_BUILD_DIR)/scan_wds_ap/ CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)"
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/ufplugins
	$(CP) $(PKG_BUILD_DIR)/scan_ap/scan_ap.so $(1)/usr/lib/ufplugins
	$(CP) $(PKG_BUILD_DIR)/scan_wds_ap/scan_wds_ap.so $(1)/usr/lib/ufplugins
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

