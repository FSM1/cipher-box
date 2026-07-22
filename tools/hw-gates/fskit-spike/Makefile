# Gate-5 FSKit spike build (CLT-only; no Xcode). Ad-hoc signed with the
# restricted FSKit entitlements — requires SIP disabled and
# boot-args=amfi_get_out_of_my_way=1 on the measurement VM.

BUILD    := build
APP      := $(BUILD)/Gate5Host.app
APPEX    := $(APP)/Contents/Extensions/Gate5FSModule.appex
LSREG    := /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

FRAMEWORKS := -framework Foundation -framework FSKit

all: $(BUILD)/g5mount app

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/Gate5FS.o: module/Gate5FS.m module/Gate5FS.h | $(BUILD)
	clang -c -fobjc-arc -O2 -Wall -o $@ module/Gate5FS.m

$(BUILD)/Gate5FSModule: module/main.swift $(BUILD)/Gate5FS.o
	swiftc -O -parse-as-library -import-objc-header module/Gate5FS.h \
		-framework ExtensionFoundation $(FRAMEWORKS) \
		-Xlinker -e -Xlinker _NSExtensionMain \
		-o $@ module/main.swift $(BUILD)/Gate5FS.o

$(BUILD)/Gate5Host: host/main.c | $(BUILD)
	clang -O2 -o $@ host/main.c

$(BUILD)/g5mount: client/g5mount.m client/client.entitlements | $(BUILD)
	clang -fobjc-arc -O2 -Wall $(FRAMEWORKS) -o $@ client/g5mount.m
	codesign -s - -f --entitlements client/client.entitlements $@

app: $(BUILD)/Gate5FSModule $(BUILD)/Gate5Host
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APPEX)/Contents/MacOS
	cp host/Info.plist $(APP)/Contents/Info.plist
	cp $(BUILD)/Gate5Host $(APP)/Contents/MacOS/Gate5Host
	cp module/Info.plist $(APPEX)/Contents/Info.plist
	cp $(BUILD)/Gate5FSModule $(APPEX)/Contents/MacOS/Gate5FSModule
	codesign -s - -f --entitlements module/module.entitlements $(APPEX)
	codesign -s - -f $(APP)
	codesign -vv $(APPEX)

install: app
	rm -rf /Applications/Gate5Host.app
	cp -R $(APP) /Applications/Gate5Host.app
	$(LSREG) -f /Applications/Gate5Host.app
	pluginkit -a /Applications/Gate5Host.app/Contents/Extensions/Gate5FSModule.appex || true
	pluginkit -m -v -p com.apple.fskit.fsmodule

clean:
	rm -rf $(BUILD)

.PHONY: all app install clean
