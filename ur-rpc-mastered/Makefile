include $(TOPDIR)/rules.mk

PKG_NAME:=ur-rpc-super
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ur-rpc-super
  SECTION:=net
  CATEGORY:=Network
  TITLE:= $(PKG_NAME)
  DEPENDS:=
  MAINTAINER:=Fehmi Yousfi <fehmi_yousfi@hotmail.com>
endef

define Package/ur-rpc-super/description
	mosquitto rebuild for cross platform usage with TLS/SSL encryption validation (Super Broker)	
endef

define Build/Configure
    # Empty body to skip the configure step
endef

define Build/Prepare
	if [ ! -d $(PKG_BUILD_DIR) ]; then \
		mkdir -p $(PKG_BUILD_DIR); \
	elif [ -n "$(ls -A $(PKG_BUILD_DIR))" ]; then \
		rm -r $(PKG_BUILD_DIR); \
		mkdir -p $(PKG_BUILD_DIR); \
	else \
		rm -r $(PKG_BUILD_DIR); \
		mkdir -p $(PKG_BUILD_DIR); \
	fi
	$(CP) ./pkg_src* $(PKG_BUILD_DIR)
endef

define Build/Compile
	echo "Building $(PKG_NAME) $(PKG_VERSION) in $(PKG_BUILD_DIR)"
	$(MAKE) -C $(PKG_BUILD_DIR)/pkg_src CC=$(TARGET_CC) CXX=$(TARGET_CXX)
	cp $(PKG_BUILD_DIR)/pkg_src/build/mqtt_broker $(PKG_BUILD_DIR)/$(PKG_NAME)
endef

define Package/ur-rpc-super/install
	$(INSTALL_DIR) $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/bin/$(PKG_NAME)
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ur-rpc-super.init $(1)/etc/init.d/ur-rpc-super
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/ur-rpc-super $(1)/etc/config/ur-rpc-super

	$(INSTALL_DIR) $(1)/etc/ultima-stack
	$(INSTALL_CONF) ./files/default-configs/broker_super_ssl.json $(1)/etc/ultima-stack/broker_super_ssl.json
	$(INSTALL_CONF) ./files/default-configs/broker_super_normal.json $(1)/etc/ultima-stack/broker_super_normal.json
	$(INSTALL_DIR) $(1)/etc/ultima-stack/certs
	$(INSTALL_CONF) ./files/certs/ca.crt $(1)/etc/ultima-stack/certs/ca.crt
	$(INSTALL_CONF) ./files/certs/ca.key $(1)/etc/ultima-stack/certs/ca.key
	$(INSTALL_CONF) ./files/certs/ca.srl $(1)/etc/ultima-stack/certs/ca.srl
	$(INSTALL_CONF) ./files/certs/server.crt $(1)/etc/ultima-stack/certs/server.crt
	$(INSTALL_CONF) ./files/certs/server.key $(1)/etc/ultima-stack/certs/server.key

endef

define Build/clean
	rm -rf $(PKG_BUILD_DIR)
endef

$(eval $(call BuildPackage,ur-rpc-super))
