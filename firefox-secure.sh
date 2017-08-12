#!/bin/bash
USER_JS="user.js"
LINUX_CONFIG_DIR="~/.mozilla/firefox/*.default/"
MAC_CONFIG_DIR="~/Library/Application\ Support/Firefox/Profiles/*.default/"

if [ -d "$LINUX_CONFIG_DIR" ]; then
    cd "$LINUX_CONFIG_DIR/$USER_JS"
elif [ -d "$MAC_CONFIG_DIR" ]; then
    cd "$MAC_CONFIG_DIR/$USER_JS"
else
    echo "Could not find firefox configuration. Exiting."
fi

> $USER_JS
#PREF: Disable Service Workers
#https://developer.mozilla.org/en-US/docs/Web/API/Worker
#https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorker_API
#https://wiki.mozilla.org/Firefox/Push_Notifications#Service_Workers
#NOTICE: Disabling ServiceWorkers breaks functionality on some sites (Google Street View...)
#Unknown security implications
#CVE-2016-5259, CVE-2016-2812, CVE-2016-1949, CVE-2016-5287 (fixed)
echo -e "user_pref(\"dom.serviceWorkers.enabled\",				false);" >> $USER_JS

#PREF: Disable Web Workers
#https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers
#https://www.w3schools.com/html/html5_webworkers.asp
echo -e "user_pref(\"dom.workers.enabled\",					false);" >> $USER_JS

#PREF: Disable web notifications
#https://support.mozilla.org/t5/Firefox/I-can-t-find-Firefox-menu-I-m-trying-to-opt-out-of-Web-Push-and/m-p/1317495#M1006501
echo -e "user_pref(\"dom.webnotifications.enabled\",			false);" >> $USER_JS

#PREF: Disable DOM timing API
#https://wiki.mozilla.org/Security/Reviews/Firefox/NavigationTimingAPI
#https://www.w3.org/TR/navigation-timing/#privacy
echo -e "user_pref(\"dom.enable_performance\",				false);" >> $USER_JS

#PREF: Make sure the User Timing API does not provide a new high resolution timestamp
#https://trac.torproject.org/projects/tor/ticket/16336
#https://www.w3.org/TR/2013/REC-user-timing-20131212/#privacy-security
echo -e "user_pref(\"dom.enable_user_timing\",				false);" >> $USER_JS

#PREF: Disable Web Audio API
#https://bugzilla.mozilla.org/show_bug.cgi?id=1288359
echo -e "user_pref(\"dom.webaudio.enabled\",				false);" >> $USER_JS

#PREF: Disable Location-Aware Browsing (geolocation)
#https://www.mozilla.org/en-US/firefox/geolocation/
echo -e "user_pref(\"geo.enabled\",					false);" >> $USER_JS

#PREF: When geolocation is enabled, use Mozilla geolocation service instead of Google
#https://bugzilla.mozilla.org/show_bug.cgi?id=689252
echo -e "user_pref(\"geo.wifi.uri\", \"https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%\");" >> $USER_JS

#PREF: When geolocation is enabled, don't log geolocation requests to the console
echo -e "user_pref(\"geo.wifi.logging.enabled\", false);" >> $USER_JS

#PREF: Disable raw TCP socket support (mozTCPSocket)
#https://trac.torproject.org/projects/tor/ticket/18863
#https://www.mozilla.org/en-US/security/advisories/mfsa2015-97/
#https://developer.mozilla.org/docs/Mozilla/B2G_OS/API/TCPSocket
echo -e "user_pref(\"dom.mozTCPSocket.enabled\",				false);" >> $USER_JS

#PREF: Disable DOM storage (disabled)
#http://kb.mozillazine.org/Dom.storage.enabled
#https://html.spec.whatwg.org/multipage/webstorage.html
#NOTICE-DISABLED: Disabling DOM storage is known to cause`TypeError: localStorage is null` errors
#echo -e "user_pref(\"dom.storage.enabled\",		false);" >> $USER_JS

#PREF: Disable leaking network/browser connection information via Javascript
#Network Information API provides general information about the system's connection type (WiFi, cellular, etc.)
#https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API
#https://wicg.github.io/netinfo/#privacy-considerations
#https://bugzilla.mozilla.org/show_bug.cgi?id=960426
echo -e "user_pref(\"dom.netinfo.enabled\",				false);" >> $USER_JS

#PREF: Disable WebRTC entirely to prevent leaking internal IP addresses (Firefox < 42)
#NOTICE: Disabling WebRTC breaks peer-to-peer file sharing tools (reep.io ...)
echo -e "user_pref(\"media.peerconnection.enabled\",			false);" >> $USER_JS

#PREF: Don't reveal your internal IP when WebRTC is enabled (Firefox >= 42)
#https://wiki.mozilla.org/Media/WebRTC/Privacy
#https://github.com/beefproject/beef/wiki/Module%3A-Get-Internal-IP-WebRTC
echo -e "user_pref(\"media.peerconnection.ice.default_address_only\",	true);" >> $USER_JS #Firefox 42-51
echo -e "user_pref(\"media.peerconnection.ice.no_host\",			true);" >> $USER_JS #Firefox >= 52

#PREF: Disable WebRTC getUserMedia, screen sharing, audio capture, video capture
#https://wiki.mozilla.org/Media/getUserMedia
#https://blog.mozilla.org/futurereleases/2013/01/12/capture-local-camera-and-microphone-streams-with-getusermedia-now-enabled-in-firefox/
#https://developer.mozilla.org/en-US/docs/Web/API/Navigator
echo -e "user_pref(\"media.navigator.enabled\",				false);" >> $USER_JS
echo -e "user_pref(\"media.navigator.video.enabled\",			false);" >> $USER_JS
echo -e "user_pref(\"media.getusermedia.screensharing.enabled\",		false);" >> $USER_JS
echo -e "user_pref(\"media.getusermedia.audiocapture.enabled\",		false);" >> $USER_JS

#PREF: Disable battery API (Firefox < 52)
#https://developer.mozilla.org/en-US/docs/Web/API/BatteryManager
#https://bugzilla.mozilla.org/show_bug.cgi?id=1313580
echo -e "user_pref(\"dom.battery.enabled\",				false);" >> $USER_JS

#PREF: Disable telephony API
#https://wiki.mozilla.org/WebAPI/Security/WebTelephony
echo -e "user_pref(\"dom.telephony.enabled\",				false);" >> $USER_JS

#PREF: Disable "beacon" asynchronous HTTP transfers (used for analytics)
#https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
echo -e "user_pref(\"beacon.enabled\",					false);" >> $USER_JS

#PREF: Disable clipboard event detection (onCut/onCopy/onPaste) via Javascript
#NOTICE: Disabling clipboard events breaks Ctrl+C/X/V copy/cut/paste functionaility in JS-based web applications (Google Docs...)
#https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/dom.event.clipboardevents.enabled
echo -e "user_pref(\"dom.event.clipboardevents.enabled\",			false);" >> $USER_JS

#PREF: Disable "copy to clipboard" functionality via Javascript (Firefox >= 41)
#NOTICE: Disabling clipboard operations will break legitimate JS-based "copy to clipboard" functionality
#https://hg.mozilla.org/mozilla-central/rev/2f9f8ea4b9c3
echo -e "user_pref(\"dom.allow_cut_copy\", false);" >> $USER_JS

#PREF: Disable speech recognition
#https://dvcs.w3.org/hg/speech-api/raw-file/tip/speechapi.html
#https://developer.mozilla.org/en-US/docs/Web/API/SpeechRecognition
#https://wiki.mozilla.org/HTML5_Speech_API
echo -e "user_pref(\"media.webspeech.recognition.enable\",			false);" >> $USER_JS

#PREF: Disable speech synthesis
#https://developer.mozilla.org/en-US/docs/Web/API/SpeechSynthesis
echo -e "user_pref(\"media.webspeech.synth.enabled\",			false);" >> $USER_JS

#PREF: Disable sensor API
#https://wiki.mozilla.org/Sensor_API
echo -e "user_pref(\"device.sensors.enabled\",				false);" >> $USER_JS

#PREF: Disable pinging URIs specified in HTML <a> ping= attributes
#http://kb.mozillazine.org/Browser.send_pings
echo -e "user_pref(\"browser.send_pings\",					false);" >> $USER_JS

#PREF: When browser pings are enabled, only allow pinging the same host as the origin page
#http://kb.mozillazine.org/Browser.send_pings.require_same_host
echo -e "user_pref(\"browser.send_pings.require_same_host\",		true);" >> $USER_JS

#PREF: Disable IndexedDB (disabled)
#https://developer.mozilla.org/en-US/docs/IndexedDB
#https://en.wikipedia.org/wiki/Indexed_Database_API
#https://wiki.mozilla.org/Security/Reviews/Firefox4/IndexedDB_Security_Review
#http://forums.mozillazine.org/viewtopic.php?p=13842047
#https://github.com/pyllyukko/$USER_JS/issues/8
#NOTICE-DISABLED: IndexedDB could be used for tracking purposes, but is required for some add-ons to work (notably uBlock), so is left enabled
#echo -e "user_pref(\"dom.indexedDB.enabled\",		false);" >> $USER_JS

#TODO: "Access Your Location" "Maintain Offline Storage" "Show Notifications"

#PREF: Disable gamepad API to prevent USB device enumeration
#https://www.w3.org/TR/gamepad/
#https://trac.torproject.org/projects/tor/ticket/13023
echo -e "user_pref(\"dom.gamepad.enabled\",				false);" >> $USER_JS

#PREF: Disable virtual reality devices APIs
#https://developer.mozilla.org/en-US/Firefox/Releases/36#Interfaces.2FAPIs.2FDOM
#https://developer.mozilla.org/en-US/docs/Web/API/WebVR_API
echo -e "user_pref(\"dom.vr.enabled\",					false);" >> $USER_JS

#PREF: Disable vibrator API
echo -e "user_pref(\"dom.vibrator.enabled\",           false);" >> $USER_JS

#PREF: Disable resource timing API
#https://www.w3.org/TR/resource-timing/#privacy-security
echo -e "user_pref(\"dom.enable_resource_timing\",				false);" >> $USER_JS

#PREF: Disable Archive API (Firefox < 54)
#https://wiki.mozilla.org/WebAPI/ArchiveAPI
#https://bugzilla.mozilla.org/show_bug.cgi?id=1342361
echo -e "user_pref(\"dom.archivereader.enabled\",				false);" >> $USER_JS

#PREF: Disable webGL
#https://en.wikipedia.org/wiki/WebGL
#https://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
echo -e "user_pref(\"webgl.disabled\",					true);" >> $USER_JS
#PREF: When webGL is enabled, use the minimum capability mode
echo -e "user_pref(\"webgl.min_capability_mode\",				true);" >> $USER_JS
#PREF: When webGL is enabled, disable webGL extensions
#https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API#WebGL_debugging_and_testing
echo -e "user_pref(\"webgl.disable-extensions\",				true);" >> $USER_JS
#PREF: When webGL is enabled, force enabling it even when layer acceleration is not supported
#https://trac.torproject.org/projects/tor/ticket/18603
echo -e "user_pref(\"webgl.disable-fail-if-major-performance-caveat\",	true);" >> $USER_JS
#PREF: When webGL is enabled, do not expose information about the graphics driver
#https://bugzilla.mozilla.org/show_bug.cgi?id=1171228
#https://developer.mozilla.org/en-US/docs/Web/API/WEBGL_debug_renderer_info
echo -e "user_pref(\"webgl.enable-debug-renderer-info\",			false);" >> $USER_JS
#somewhat related...
#echo -e "user_pref(\"pdfjs.enableWebGL\",					false);" >> $USER_JS

#PREF: Disable face detection
echo -e "user_pref(\"camera.control.face_detection.enabled\",		false);" >> $USER_JS

#PREF: Set the default search engine to DuckDuckGo (disabled)
#https://support.mozilla.org/en-US/questions/948134
echo -e "user_pref(\"browser.search.defaultenginename\",		\"DuckDuckGo\");" >> $USER_JS
echo -e "user_pref(\"browser.search.order.1\",				\"DuckDuckGo\");" >> $USER_JS
echo -e "user_pref(\"keyword.URL\", 							\"https://duckduckgo.com/html/?q=!+\");" >> $USER_JS  

#PREF: Disable GeoIP lookup on your address to set default search engine region
#https://trac.torproject.org/projects/tor/ticket/16254
#https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_geolocation-for-default-search-engine
echo -e "user_pref(\"browser.search.countryCode\",				\"US\");" >> $USER_JS
echo -e "user_pref(\"browser.search.region\",				\"US\");" >> $USER_JS
echo -e "user_pref(\"browser.search.geoip.url\",				\"\");" >> $USER_JS

#PREF: Set Accept-Language HTTP header to en-US regardless of Firefox localization
#https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
echo -e "user_pref(\"intl.accept_languages\",				\"en-us, en\");" >> $USER_JS

#PREF: Set Firefox locale to en-US
#http://kb.mozillazine.org/General.useragent.locale
echo -e "user_pref(\"general.useragent.locale\",				\"en-US\");" >> $USER_JS

#PREF: Don't use OS values to determine locale, force using Firefox locale setting
#http://kb.mozillazine.org/Intl.locale.matchOS
echo -e "user_pref(\"intl.locale.matchOS\",				false);" >> $USER_JS

#PREF: Don't use Mozilla-provided location-specific search engines
echo -e "user_pref(\"browser.search.geoSpecificDefaults\",			false);" >> $USER_JS

#PREF: Do not automatically send selection to clipboard on some Linux platforms
#http://kb.mozillazine.org/Clipboard.autocopy
echo -e "user_pref(\"clipboard.autocopy\",					false);" >> $USER_JS

#PREF: Prevent leaking application locale/date format using JavaScript
#https://bugzilla.mozilla.org/show_bug.cgi?id=867501
#https://hg.mozilla.org/mozilla-central/rev/52d635f2b33d
echo -e "user_pref(\"javascript.use_us_english_locale\",			true);" >> $USER_JS

#PREF: Do not submit invalid URIs entered in the address bar to the default search engine
#http://kb.mozillazine.org/Keyword.enabled
echo -e "user_pref(\"keyword.enabled\",					false);" >> $USER_JS

#PREF: Don't trim HTTP off of URLs in the address bar.
#https://bugzilla.mozilla.org/show_bug.cgi?id=665580
echo -e "user_pref(\"browser.urlbar.trimURLs\",				false);" >> $USER_JS

#PREF: Don't try to guess domain names when entering an invalid domain name in URL bar
#http://www-archive.mozilla.org/docs/end-user/domain-guessing.html
echo -e "user_pref(\"browser.fixup.alternate.enabled\",			false);" >> $USER_JS

#PREF: When browser.fixup.alternate.enabled is enabled, strip password from 'user:password@...' URLs
#https://github.com/pyllyukko/$USER_JS/issues/290#issuecomment-303560851
echo -e "user_pref(\"browser.fixup.hide_user_pass\", true);" >> $USER_JS

#PREF: Send DNS request through SOCKS when SOCKS proxying is in use
#https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/WebBrowsers
echo -e "user_pref(\"network.proxy.socks_remote_dns\",			true);" >> $USER_JS

#PREF: Don't monitor OS online/offline connection state
#https://trac.torproject.org/projects/tor/ticket/18945
echo -e "user_pref(\"network.manage-offline-status\",			false);" >> $USER_JS

#PREF: Enforce Mixed Active Content Blocking
#https://support.mozilla.org/t5/Protect-your-privacy/Mixed-content-blocking-in-Firefox/ta-p/10990
#https://developer.mozilla.org/en-US/docs/Site_Compatibility_for_Firefox_23#Non-SSL_contents_on_SSL_pages_are_blocked_by_default
#https://blog.mozilla.org/tanvi/2013/04/10/mixed-content-blocking-enabled-in-firefox-23/
echo -e "user_pref(\"security.mixed_content.block_active_content\",	true);" >> $USER_JS

#PREF: Enforce Mixed Passive Content blocking (a.k.a. Mixed Display Content)
#NOTICE: Enabling Mixed Display Content blocking can prevent images/styles... from loading properly when connection to the website is only partially secured
echo -e "user_pref(\"security.mixed_content.block_display_content\",	true);" >> $USER_JS

#PREF: Disable JAR from opening Unsafe File Types
#http://kb.mozillazine.org/Network.jar.open-unsafe-types
#CIS Mozilla Firefox 24 ESR v1.0.0 - 3.7 
echo -e "user_pref(\"network.jar.open-unsafe-types\",			false);" >> $USER_JS

#CIS 2.7.4 Disable Scripting of Plugins by JavaScript
#http://forums.mozillazine.org/viewtopic.php?f=7&t=153889
echo -e "user_pref(\"security.xpconnect.plugin.unrestricted\",		false);" >> $USER_JS

#PREF: Set File URI Origin Policy
#http://kb.mozillazine.org/Security.fileuri.strict_origin_policy
#CIS Mozilla Firefox 24 ESR v1.0.0 - 3.8
echo -e "user_pref(\"security.fileuri.strict_origin_policy\",		true);" >> $USER_JS

#PREF: Disable Displaying Javascript in History URLs
#http://kb.mozillazine.org/Browser.urlbar.filter.javascript
#CIS 2.3.6 
echo -e "user_pref(\"browser.urlbar.filter.javascript\",			true);" >> $USER_JS

#PREF: Disable asm.js
#http://asmjs.org/
#https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/
#https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/
#https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2712
echo -e "user_pref(\"javascript.options.asmjs\",				false);" >> $USER_JS

#PREF: Disable SVG in OpenType fonts
#https://wiki.mozilla.org/SVGOpenTypeFonts
#https://github.com/iSECPartners/publications/tree/master/reports/Tor%20Browser%20Bundle
echo -e "user_pref(\"gfx.font_rendering.opentype_svg.enabled\",		false);" >> $USER_JS

#PREF: Disable in-content SVG rendering (Firefox >= 53)
#NOTICE: Disabling SVG support breaks many UI elements on many sites
#https://bugzilla.mozilla.org/show_bug.cgi?id=1216893
#https://github.com/iSECPartners/publications/raw/master/reports/Tor%20Browser%20Bundle/Tor%20Browser%20Bundle%20-%20iSEC%20Deliverable%201.3.pdf#16
echo -e "user_pref(\"svg.disabled\", true);" >> $USER_JS


#PREF: Disable video stats to reduce fingerprinting threat
#https://bugzilla.mozilla.org/show_bug.cgi?id=654550
#https://github.com/pyllyukko/$USER_JS/issues/9#issuecomment-100468785
#https://github.com/pyllyukko/$USER_JS/issues/9#issuecomment-148922065
echo -e "user_pref(\"media.video_stats.enabled\",				false);" >> $USER_JS

#PREF: Don't reveal build ID
#Value taken from Tor Browser
#https://bugzilla.mozilla.org/show_bug.cgi?id=583181
echo -e "user_pref(\"general.buildID.override\",				\"20100101\");" >> $USER_JS

#PREF: Prevent font fingerprinting
#https://browserleaks.com/fonts
#https://github.com/pyllyukko/$USER_JS/issues/120
echo -e "user_pref(\"browser.display.use_document_fonts\",			0);" >> $USER_JS

#PREF: Enable only whitelisted URL protocol handlers
#http://kb.mozillazine.org/Network.protocol-handler.external-default
#http://kb.mozillazine.org/Network.protocol-handler.warn-external-default
#http://kb.mozillazine.org/Network.protocol-handler.expose.%28protocol%29
#https://news.ycombinator.com/item?id=13047883
#https://bugzilla.mozilla.org/show_bug.cgi?id=167475
#https://github.com/pyllyukko/$USER_JS/pull/285#issuecomment-298124005
#NOTICE: Disabling nonessential protocols breaks all interaction with custom protocols such as mailto:, irc:, magnet: ... and breaks opening third-party mail/messaging/torrent/... clients when clicking on links with these protocols
#TODO: Add externally-handled protocols from Windows 8.1 and Windows 10 (currently contains protocols only from Linux and Windows 7) that might pose a similar threat (see e.g. https://news.ycombinator.com/item?id=13044991)
#TODO: Add externally-handled protocols from Mac OS X that might pose a similar threat (see e.g. https://news.ycombinator.com/item?id=13044991)
#If you want to enable a protocol, set network.protocol-handler.expose.(protocol) to true and network.protocol-handler.external.(protocol) to:
#  * true, if the protocol should be handled by an external application
#  * false, if the protocol should be handled internally by Firefox
echo -e "user_pref(\"network.protocol-handler.warn-external-default\",	true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.http\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.https\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.javascript\",	false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.moz-extension\",	false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.ftp\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.file\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.about\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.chrome\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.blob\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.external.data\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose-all\",		false);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.http\",		true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.https\",		true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.javascript\",		true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.moz-extension\",	true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.ftp\",		true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.file\",		true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.about\",		true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.chrome\",		true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.blob\",		true);" >> $USER_JS
echo -e "user_pref(\"network.protocol-handler.expose.data\",		true);" >> $USER_JS

#PREF: Ensure you have a security delay when installing add-ons (milliseconds)
#http://kb.mozillazine.org/Disable_extension_install_delay_-_Firefox
#http://www.squarefree.com/2004/07/01/race-conditions-in-security-dialogs/
echo -e "user_pref(\"security.dialog_enable_delay\",			1000);" >> $USER_JS

#PREF: Require signatures
#https://wiki.mozilla.org/Addons/Extension_Signing
#echo -e "user_pref(\"xpinstall.signatures.required\",		true);" >> $USER_JS

#PREF: Opt-out of add-on metadata updates
#https://blog.mozilla.org/addons/how-to-opt-out-of-add-on-metadata-updates/
echo -e "user_pref(\"extensions.getAddons.cache.enabled\",			false);" >> $USER_JS

#PREF: Opt-out of themes (Persona) updates
#https://support.mozilla.org/t5/Firefox/how-do-I-prevent-autoamtic-updates-in-a-50-user-environment/td-p/144287
echo -e "user_pref(\"lightweightThemes.update.enabled\",			false);" >> $USER_JS

#PREF: Disable Flash Player NPAPI plugin
#http://kb.mozillazine.org/Flash_plugin
echo -e "user_pref(\"plugin.state.flash\",					0);" >> $USER_JS

#PREF: Disable Java NPAPI plugin
echo -e "user_pref(\"plugin.state.java\",					0);" >> $USER_JS

#PREF: Disable sending Flash Player crash reports
echo -e "user_pref(\"dom.ipc.plugins.flash.subprocess.crashreporter.enabled\",	false);" >> $USER_JS

#PREF: When Flash crash reports are enabled, don't send the visited URL in the crash report
echo -e "user_pref(\"dom.ipc.plugins.reportCrashURL\",			false);" >> $USER_JS

#PREF: When Flash is enabled, download and use Mozilla SWF URIs blocklist
#https://bugzilla.mozilla.org/show_bug.cgi?id=1237198
#https://github.com/mozilla-services/shavar-plugin-blocklist
echo -e "user_pref(\"browser.safebrowsing.blockedURIs.enabled\", true);" >> $USER_JS

#PREF: Disable Shumway (Mozilla Flash renderer)
#https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Shumway
echo -e "pref(\"shumway.disabled\", true);" >> $USER_JS

#PREF: Disable Gnome Shell Integration NPAPI plugin
echo -e "user_pref(\"plugin.state.libgnome-shell-browser-plugin\",		0);" >> $USER_JS

#PREF: Disable the bundled OpenH264 video codec (disabled)
#http://forums.mozillazine.org/viewtopic.php?p=13845077&sid=28af2622e8bd8497b9113851676846b1#p13845077
#echo -e "user_pref(\"media.gmp-provider.enabled\",		false);" >> $USER_JS

#PREF: Enable plugins click-to-play
#https://wiki.mozilla.org/Firefox/Click_To_Play
#https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
echo -e "user_pref(\"plugins.click_to_play\",				true);" >> $USER_JS

#PREF: Updates addons automatically
#https://blog.mozilla.org/addons/how-to-turn-off-add-on-updates/
echo -e "user_pref(\"extensions.update.enabled\",				true);" >> $USER_JS

#PREF: Enable add-on and certificate blocklists (OneCRL) from Mozilla
#https://wiki.mozilla.org/Blocklisting
#https://blocked.cdn.mozilla.net/
#http://kb.mozillazine.org/Extensions.blocklist.enabled
#http://kb.mozillazine.org/Extensions.blocklist.url
#https://blog.mozilla.org/security/2015/03/03/revoking-intermediate-certificates-introducing-onecrl/
#Updated at interval defined in extensions.blocklist.interval (default: 86400)
echo -e "user_pref(\"extensions.blocklist.enabled\",			true);" >> $USER_JS
echo -e "user_pref(\"services.blocklist.update_enabled\",			true);" >> $USER_JS

#PREF: Decrease system information leakage to Mozilla blocklist update servers
#https://trac.torproject.org/projects/tor/ticket/16931
echo -e "user_pref(\"extensions.blocklist.url\",				\"https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/\");" >> $USER_JS

#PREF: Disable WebIDE
#https://trac.torproject.org/projects/tor/ticket/16222
#https://developer.mozilla.org/docs/Tools/WebIDE
echo -e "user_pref(\"devtools.webide.enabled\",				false);" >> $USER_JS
echo -e "user_pref(\"devtools.webide.autoinstallADBHelper\",		false);" >> $USER_JS
echo -e "user_pref(\"devtools.webide.autoinstallFxdtAdapters\",		false);" >> $USER_JS

#PREF: Disable remote debugging
#https://developer.mozilla.org/en-US/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop
#https://developer.mozilla.org/en-US/docs/Tools/Tools_Toolbox#Advanced_settings
echo -e "user_pref(\"devtools.debugger.remote-enabled\",			false);" >> $USER_JS
echo -e "user_pref(\"devtools.chrome.enabled\",				false);" >> $USER_JS
echo -e "user_pref(\"devtools.debugger.force-local\",			true);" >> $USER_JS

#PREF: Disable Mozilla telemetry/experiments
#https://wiki.mozilla.org/Platform/Features/Telemetry
#https://wiki.mozilla.org/Privacy/Reviews/Telemetry
#https://wiki.mozilla.org/Telemetry
#https://www.mozilla.org/en-US/legal/privacy/firefox.html#telemetry
#https://support.mozilla.org/t5/Firefox-crashes/Mozilla-Crash-Reporter/ta-p/1715
#https://wiki.mozilla.org/Security/Reviews/Firefox6/ReviewNotes/telemetry
#https://gecko.readthedocs.io/en/latest/browser/experiments/experiments/manifest.html
#https://wiki.mozilla.org/Telemetry/Experiments
echo -e "user_pref(\"toolkit.telemetry.enabled\",				false);" >> $USER_JS
echo -e "user_pref(\"toolkit.telemetry.unified\",				false);" >> $USER_JS
echo -e "user_pref(\"experiments.supported\",				false);" >> $USER_JS
echo -e "user_pref(\"experiments.enabled\",				false);" >> $USER_JS
echo -e "user_pref(\"experiments.manifest.uri\",				\"\");" >> $USER_JS

#PREF: Disallow Necko to do A/B testing
#https://trac.torproject.org/projects/tor/ticket/13170
echo -e "user_pref(\"network.allow-experiments\",				false);" >> $USER_JS

#PREF: Disable sending Firefox crash reports to Mozilla servers
#https://wiki.mozilla.org/Breakpad
#http://kb.mozillazine.org/Breakpad
#https://dxr.mozilla.org/mozilla-central/source/toolkit/crashreporter
#https://bugzilla.mozilla.org/show_bug.cgi?id=411490
#A list of submitted crash reports can be found at about:crashes
echo -e "user_pref(\"breakpad.reportURL\",					\"\");" >> $USER_JS

#PREF: Disable sending reports of tab crashes to Mozilla (about:tabcrashed), don't nag user about unsent crash reports
#https://hg.mozilla.org/mozilla-central/file/tip/browser/app/profile/firefox.js
echo -e "user_pref(\"browser.tabs.crashReporting.sendReport\",		false);" >> $USER_JS
echo -e "user_pref(\"browser.crashReports.unsubmittedCheck.enabled\",	false);" >> $USER_JS

#PREF: Disable FlyWeb (discovery of LAN/proximity IoT devices that expose a Web interface)
#https://wiki.mozilla.org/FlyWeb
#https://wiki.mozilla.org/FlyWeb/Security_scenarios
#https://docs.google.com/document/d/1eqLb6cGjDL9XooSYEEo7mE-zKQ-o-AuDTcEyNhfBMBM/edit
#http://www.ghacks.net/2016/07/26/firefox-flyweb
echo -e "user_pref(\"dom.flyweb.enabled\",					false);" >> $USER_JS

#PREF: Disable the UITour backend
#https://trac.torproject.org/projects/tor/ticket/19047#comment:3
echo -e "user_pref(\"browser.uitour.enabled\",				false);" >> $USER_JS

#PREF: Enable Firefox Tracking Protection
#https://wiki.mozilla.org/Security/Tracking_protection
#https://support.mozilla.org/en-US/kb/tracking-protection-firefox
#https://support.mozilla.org/en-US/kb/tracking-protection-pbm
#https://kontaxis.github.io/trackingprotectionfirefox/
#https://feeding.cloud.geek.nz/posts/how-tracking-protection-works-in-firefox/
echo -e "user_pref(\"privacy.trackingprotection.enabled\",			true);" >> $USER_JS
echo -e "user_pref(\"privacy.trackingprotection.pbmode.enabled\",		true);" >> $USER_JS

#PREF: Enable contextual identity Containers feature (Firefox >= 52)
#NOTICE: Containers are not available in Private Browsing mode
#https://wiki.mozilla.org/Security/Contextual_Identity_Project/Containers
echo -e "user_pref(\"privacy.userContext.enabled\",			true);" >> $USER_JS

#PREF: Enable hardening against various fingerprinting vectors (Tor Uplift project)
#https://wiki.mozilla.org/Security/Tor_Uplift/Tracking
#https://bugzilla.mozilla.org/show_bug.cgi?id=1333933
echo -e "user_pref(\"privacy.resistFingerprinting\",			true);" >> $USER_JS

#PREF: Disable the built-in PDF viewer
#https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2743
#https://blog.mozilla.org/security/2015/08/06/firefox-exploit-found-in-the-wild/
#https://www.mozilla.org/en-US/security/advisories/mfsa2015-69/
echo -e "user_pref(\"pdfjs.disabled\",					true);" >> $USER_JS

#PREF: Disable collection/sending of the health report (healthreport.sqlite*)
#https://support.mozilla.org/en-US/kb/firefox-health-report-understand-your-browser-perf
#https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
echo -e "user_pref(\"datareporting.healthreport.uploadEnabled\",		false);" >> $USER_JS
echo -e "user_pref(\"datareporting.healthreport.service.enabled\",		false);" >> $USER_JS
echo -e "user_pref(\"datareporting.policy.dataSubmissionEnabled\",		false);" >> $USER_JS

#PREF: Disable Heartbeat  (Mozilla user rating telemetry)
#https://wiki.mozilla.org/Advocacy/heartbeat
#https://trac.torproject.org/projects/tor/ticket/19047
echo -e "user_pref(\"browser.selfsupport.url\",				\"\");" >> $USER_JS

#PREF: Disable Firefox Hello (disabled) (Firefox < 49)
#https://wiki.mozilla.org/Loop
#https://support.mozilla.org/t5/Chat-and-share/Support-for-Hello-discontinued-in-Firefox-49/ta-p/37946
#NOTICE-DISABLED: Firefox Hello requires setting `media.peerconnection.enabled` and `media.getusermedia.screensharing.enabled` to true, `security.OCSP.require` to false to work.
#echo -e "user_pref(\"loop.enabled\",		false);" >> $USER_JS

#PREF: Disable Firefox Hello metrics collection
#https://groups.google.com/d/topic/mozilla.dev.platform/nyVkCx-_sFw/discussion
echo -e "user_pref(\"loop.logDomains\",					false);" >> $USER_JS

#PREF: Enable Auto Update (disabled)
#NOTICE: Fully automatic updates are disabled and left to package management systems on Linux. Windows users may want to change this setting.
#CIS 2.1.1
#echo -e "user_pref(\"app.update.auto\",					true);" >> $USER_JS

#PREF: Enforce checking for Firefox updates
#http://kb.mozillazine.org/App.update.enabled
#NOTICE: Update check page might incorrectly report Firefox ESR as out-of-date
echo -e "user_pref(\"app.update.enabled\",                 true);" >> $USER_JS

#PREF: Enable blocking reported web forgeries
#https://wiki.mozilla.org/Security/Safe_Browsing
#http://kb.mozillazine.org/Safe_browsing
#https://support.mozilla.org/en-US/kb/how-does-phishing-and-malware-protection-work
#http://forums.mozillazine.org/viewtopic.php?f=39&t=2711237&p=12896849#p12896849
#CIS 2.3.4
echo -e "user_pref(\"browser.safebrowsing.enabled\",			true);" >> $USER_JS #Firefox < 50
echo -e "user_pref(\"browser.safebrowsing.phishing.enabled\",		true);" >> $USER_JS #firefox >= 50

#PREF: Enable blocking reported attack sites
#http://kb.mozillazine.org/Browser.safebrowsing.malware.enabled
#CIS 2.3.5
echo -e "user_pref(\"browser.safebrowsing.malware.enabled\",		true);" >> $USER_JS

#PREF: Disable querying Google Application Reputation database for downloaded binary files
#https://www.mozilla.org/en-US/firefox/39.0/releasenotes/
#https://wiki.mozilla.org/Security/Application_Reputation
echo -e "user_pref(\"browser.safebrowsing.downloads.remote.enabled\",	false);" >> $USER_JS

#PREF: Disable Pocket
#https://support.mozilla.org/en-US/kb/save-web-pages-later-pocket-firefox
#https://github.com/pyllyukko/$USER_JS/issues/143
echo -e "user_pref(\"browser.pocket.enabled\",				false);" >> $USER_JS
echo -e "user_pref(\"extensions.pocket.enabled\",				false);" >> $USER_JS

#PREF: Disable prefetching of <link rel="next"> URLs
#http://kb.mozillazine.org/Network.prefetch-next
#https://developer.mozilla.org/en-US/docs/Web/HTTP/Link_prefetching_FAQ#Is_there_a_preference_to_disable_link_prefetching.3F
echo -e "user_pref(\"network.prefetch-next\",				false);" >> $USER_JS

#PREF: Disable DNS prefetching
#http://kb.mozillazine.org/Network.dns.disablePrefetch
#https://developer.mozilla.org/en-US/docs/Web/HTTP/Controlling_DNS_prefetching
echo -e "user_pref(\"network.dns.disablePrefetch\",			true);" >> $USER_JS
echo -e "user_pref(\"network.dns.disablePrefetchFromHTTPS\",		true);" >> $USER_JS

#PREF: Disable the predictive service (Necko)
#https://wiki.mozilla.org/Privacy/Reviews/Necko
echo -e "user_pref(\"network.predictor.enabled\",				false);" >> $USER_JS

#PREF: Reject .onion hostnames before passing the to DNS
#https://bugzilla.mozilla.org/show_bug.cgi?id=1228457
#RFC 7686
echo -e "user_pref(\"network.dns.blockDotOnion\",				true);" >> $USER_JS

#PREF: Disable search suggestions in the search bar
#http://kb.mozillazine.org/Browser.search.suggest.enabled
echo -e "user_pref(\"browser.search.suggest.enabled\",			false);" >> $USER_JS

#PREF: Disable "Show search suggestions in location bar results"
echo -e "user_pref(\"browser.urlbar.suggest.searches\",			false);" >> $USER_JS
#PREF: When using the location bar, don't suggest URLs from browsing history
echo -e "user_pref(\"browser.urlbar.suggest.history\",			false);" >> $USER_JS

#PREF: Disable SSDP
#https://bugzilla.mozilla.org/show_bug.cgi?id=1111967
echo -e "user_pref(\"browser.casting.enabled\",				false);" >> $USER_JS

#PREF: Disable automatic downloading of OpenH264 codec
#https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_media-capabilities
#https://andreasgal.com/2014/10/14/openh264-now-in-firefox/
echo -e "user_pref(\"media.gmp-gmpopenh264.enabled\",			false);" >> $USER_JS
echo -e "user_pref(\"media.gmp-manager.url\",				\"\");" >> $USER_JS

#PREF: Disable speculative pre-connections
#https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_speculative-pre-connections
#https://bugzilla.mozilla.org/show_bug.cgi?id=814169
echo -e "user_pref(\"network.http.speculative-parallel-limit\",		0);" >> $USER_JS

#PREF: Disable downloading homepage snippets/messages from Mozilla
#https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_mozilla-content
#https://wiki.mozilla.org/Firefox/Projects/Firefox_Start/Snippet_Service
echo -e "user_pref(\"browser.aboutHomeSnippets.updateUrl\",		\"\");" >> $USER_JS

#PREF: Never check updates for search engines
#https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_auto-update-checking
echo -e "user_pref(\"browser.search.update\",				false);" >> $USER_JS

#PREF: Disallow NTLMv1
#https://bugzilla.mozilla.org/show_bug.cgi?id=828183
echo -e "user_pref(\"network.negotiate-auth.allow-insecure-ntlm-v1\",	false);" >> $USER_JS
#it is still allowed through HTTPS. uncomment the following to disable it completely.
#echo -e "user_pref(\"network.negotiate-auth.allow-insecure-ntlm-v1-https\",		false);" >> $USER_JS

#PREF: Enable CSP 1.1 script-nonce directive support
#https://bugzilla.mozilla.org/show_bug.cgi?id=855326
echo -e "user_pref(\"security.csp.experimentalEnabled\",			true);" >> $USER_JS

#PREF: Enable Content Security Policy (CSP)
#https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
#https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
echo -e "user_pref(\"security.csp.enable\",				true);" >> $USER_JS

#PREF: Enable Subresource Integrity
#https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
#https://wiki.mozilla.org/Security/Subresource_Integrity
echo -e "user_pref(\"security.sri.enable\",				true);" >> $USER_JS

#PREF: DNT HTTP header (disabled)
#https://www.mozilla.org/en-US/firefox/dnt/
#https://en.wikipedia.org/wiki/Do_not_track_header
#https://dnt-dashboard.mozilla.org
#https://github.com/pyllyukko/$USER_JS/issues/11
#NOTICE: Do No Track must be enabled manually
#echo -e "user_pref(\"privacy.donottrackheader.enabled\",		true);" >> $USER_JS

#PREF: Send a referer header with the target URI as the source
#https://bugzilla.mozilla.org/show_bug.cgi?id=822869
#https://github.com/pyllyukko/$USER_JS/issues/227
#NOTICE: Spoofing referers breaks functionality on websites relying on authentic referer headers
#NOTICE: Spoofing referers breaks visualisation of 3rd-party sites on the Lightbeam addon
#NOTICE: Spoofing referers disables CSRF protection on some login pages not implementing origin-header/cookie+token based CSRF protection
#TODO: https://github.com/pyllyukko/$USER_JS/issues/94, commented-out XOriginPolicy/XOriginTrimmingPolicy = 2 prefs
echo -e "user_pref(\"network.http.referer.spoofSource\",			true);" >> $USER_JS

#PREF: Don't send referer headers when following links across different domains (disabled)
#https://github.com/pyllyukko/$USER_JS/issues/227
#echo -e "user_pref(\"network.http.referer.XOriginPolicy\",		2);" >> $USER_JS

#PREF: Accept Only 1st Party Cookies
#http://kb.mozillazine.org/Network.cookie.cookieBehavior#1
#NOTICE: Blocking 3rd-party cookies breaks a number of payment gateways
#CIS 2.5.1
echo -e "user_pref(\"network.cookie.cookieBehavior\",			1);" >> $USER_JS

#PREF: Make sure that third-party cookies (if enabled) never persist beyond the session.
#https://feeding.cloud.geek.nz/posts/tweaking-cookies-for-privacy-in-firefox/
#http://kb.mozillazine.org/Network.cookie.thirdparty.sessionOnly
#https://developer.mozilla.org/en-US/docs/Cookies_Preferences_in_Mozilla#network.cookie.thirdparty.sessionOnly
echo -e "user_pref(\"network.cookie.thirdparty.sessionOnly\",		true);" >> $USER_JS

#PREF: Spoof User-agent (disabled)
#echo -e "user_pref(\"general.useragent.override\",				"Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0");" >> $USER_JS
#echo -e "user_pref(\"general.appname.override\",				"Netscape");" >> $USER_JS
#echo -e "user_pref(\"general.appversion.override\",			"5.0 (Windows)");" >> $USER_JS
#echo -e "user_pref(\"general.platform.override\",				"Win32");" >> $USER_JS
#echo -e "user_pref(\"general.oscpu.override\",				"Windows NT 6.1");" >> $USER_JS

#PREF: Permanently enable private browsing mode
#https://support.mozilla.org/en-US/kb/Private-Browsing
#https://wiki.mozilla.org/PrivateBrowsing
#NOTICE: You can not view or inspect cookies when in private browsing: https://bugzilla.mozilla.org/show_bug.cgi?id=823941
#NOTICE: When Javascript is enabled, Websites can detect use of Private Browsing mode
#NOTICE: Private browsing breaks Kerberos authentication
#NOTICE: Disables "Containers" functionality (see below)
echo -e "user_pref(\"browser.privatebrowsing.autostart\",			true);" >> $USER_JS

#PREF: Do not download URLs for the offline cache
#http://kb.mozillazine.org/Browser.cache.offline.enable
echo -e "user_pref(\"browser.cache.offline.enable\",			false);" >> $USER_JS

#PREF: Clear history when Firefox closes
#https://support.mozilla.org/en-US/kb/Clear%20Recent%20History#w_how-do-i-make-firefox-clear-my-history-automatically
#NOTICE: Installing $USER_JS will **remove your saved passwords** (https://github.com/pyllyukko/$USER_JS/issues/27)
#NOTICE: Clearing open windows on Firefox exit causes 2 windows to open when Firefox starts https://bugzilla.mozilla.org/show_bug.cgi?id=1334945
echo -e "user_pref(\"privacy.sanitize.sanitizeOnShutdown\",		true);" >> $USER_JS
echo -e "user_pref(\"privacy.clearOnShutdown.cache\",			true);" >> $USER_JS
echo -e "user_pref(\"privacy.clearOnShutdown.cookies\",			true);" >> $USER_JS
echo -e "user_pref(\"privacy.clearOnShutdown.downloads\",			true);" >> $USER_JS
echo -e "user_pref(\"privacy.clearOnShutdown.formdata\",			true);" >> $USER_JS
echo -e "user_pref(\"privacy.clearOnShutdown.history\",			true);" >> $USER_JS
echo -e "user_pref(\"privacy.clearOnShutdown.offlineApps\",		true);" >> $USER_JS
echo -e "user_pref(\"privacy.clearOnShutdown.sessions\",			true);" >> $USER_JS
echo -e "user_pref(\"privacy.clearOnShutdown.openWindows\",		true);" >> $USER_JS

#PREF: Set time range to "Everything" as default in "Clear Recent History"
echo -e "user_pref(\"privacy.sanitize.timeSpan\",				0);" >> $USER_JS

#PREF: Clear everything but "Site Preferences" in "Clear Recent History"
echo -e "user_pref(\"privacy.cpd.offlineApps\",				true);" >> $USER_JS
echo -e "user_pref(\"privacy.cpd.cache\",					true);" >> $USER_JS
echo -e "user_pref(\"privacy.cpd.cookies\",				true);" >> $USER_JS
echo -e "user_pref(\"privacy.cpd.downloads\",				true);" >> $USER_JS
echo -e "user_pref(\"privacy.cpd.formdata\",				true);" >> $USER_JS
echo -e "user_pref(\"privacy.cpd.history\",				true);" >> $USER_JS
echo -e "user_pref(\"privacy.cpd.sessions\",				true);" >> $USER_JS

#PREF: Don't remember browsing history
echo -e "user_pref(\"places.history.enabled\",				false);" >> $USER_JS

#PREF: Disable disk cache
#http://kb.mozillazine.org/Browser.cache.disk.enable
echo -e "user_pref(\"browser.cache.disk.enable\",				false);" >> $USER_JS

#PREF: Disable memory cache (disabled)
#http://kb.mozillazine.org/Browser.cache.memory.enable
#echo -e "user_pref(\"browser.cache.memory.enable\",		false);" >> $USER_JS

#PREF: Disable Caching of SSL Pages
#CIS Version 1.2.0 October 21st, 2011 2.5.8
#http://kb.mozillazine.org/Browser.cache.disk_cache_ssl
echo -e "user_pref(\"browser.cache.disk_cache_ssl\",			false);" >> $USER_JS

#PREF: Disable download history
#CIS Version 1.2.0 October 21st, 2011 2.5.5
echo -e "user_pref(\"browser.download.manager.retention\",			0);" >> $USER_JS

#PREF: Disable password manager
#CIS Version 1.2.0 October 21st, 2011 2.5.2
echo -e "user_pref(\"signon.rememberSignons\",				false);" >> $USER_JS

#PREF: Disable form autofill, don't save information entered in web page forms and the Search Bar
echo -e "user_pref(\"browser.formfill.enable\",				false);" >> $USER_JS

#PREF: Cookies expires at the end of the session (when the browser closes)
#http://kb.mozillazine.org/Network.cookie.lifetimePolicy#2
echo -e "user_pref(\"network.cookie.lifetimePolicy\",			2);" >> $USER_JS

#PREF: Require manual intervention to autofill known username/passwords sign-in forms
#http://kb.mozillazine.org/Signon.autofillForms
#https://www.torproject.org/projects/torbrowser/design/#identifier-linkability
echo -e "user_pref(\"signon.autofillForms\",				false);" >> $USER_JS

#PREF: When username/password autofill is enabled, still disable it on non-HTTPS sites
#https://hg.mozilla.org/integration/mozilla-inbound/rev/f0d146fe7317
echo -e "user_pref(\"signon.autofillForms.http\",				false);" >> $USER_JS

#PREF: Show in-content login form warning UI for insecure login fields
#https://hg.mozilla.org/integration/mozilla-inbound/rev/f0d146fe7317
echo -e "user_pref(\"security.insecure_field_warning.contextual.enabled\", true);" >> $USER_JS

#PREF: Disable the password manager for pages with autocomplete=off (disabled)
#https://bugzilla.mozilla.org/show_bug.cgi?id=956906
#OWASP ASVS V9.1
#Does not prevent any kind of auto-completion (see browser.formfill.enable, signon.autofillForms)
#echo -e "user_pref(\"signon.storeWhenAutocompleteOff\",			false);" >> $USER_JS

#PREF: Delete Search and Form History
#CIS Version 1.2.0 October 21st, 2011 2.5.6
echo -e "user_pref(\"browser.formfill.expire_days\",			0);" >> $USER_JS

#PREF: Clear SSL Form Session Data
#http://kb.mozillazine.org/Browser.sessionstore.privacy_level#2
#Store extra session data for unencrypted (non-HTTPS) sites only.
#CIS Version 1.2.0 October 21st, 2011 2.5.7
#NOTE: CIS says 1, we use 2
echo -e "user_pref(\"browser.sessionstore.privacy_level\",			2);" >> $USER_JS

#PREF: Delete temporary files on exit
#https://bugzilla.mozilla.org/show_bug.cgi?id=238789
echo -e "user_pref(\"browser.helperApps.deleteTempFileOnExit\",		true);" >> $USER_JS

#PREF: Do not create screenshots of visited pages (relates to the "new tab page" feature)
#https://support.mozilla.org/en-US/questions/973320
#https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/browser.pagethumbnails.capturing_disabled
echo -e "user_pref(\"browser.pagethumbnails.capturing_disabled\",		true);" >> $USER_JS

#PREF: Don't fetch and permanently store favicons for Windows .URL shortcuts created by drag and drop
#NOTICE: .URL shortcut files will be created with a generic icon
#Favicons are stored as .ico files in $profile_dir\shortcutCache
echo -e "user_pref(\"browser.shell.shortcutFavicons\",					false);" >> $USER_JS

#PREF: Disable bookmarks backups (default: 15)
#http://kb.mozillazine.org/Browser.bookmarks.max_backups
echo -e "user_pref(\"browser.bookmarks.max_backups\", 0);" >> $USER_JS

#PREF: Enable insecure password warnings (login forms in non-HTTPS pages)
#https://blog.mozilla.org/tanvi/2016/01/28/no-more-passwords-over-http-please/
#https://bugzilla.mozilla.org/show_bug.cgi?id=1319119
#https://bugzilla.mozilla.org/show_bug.cgi?id=1217156
echo -e "user_pref(\"security.insecure_password.ui.enabled\",		true);" >> $USER_JS

#PREF: Disable right-click menu manipulation via JavaScript (disabled)
#echo -e "user_pref(\"dom.event.contextmenu.enabled\",		false);" >> $USER_JS

#PREF: Disable "Are you sure you want to leave this page?" popups on page close
#https://support.mozilla.org/en-US/questions/1043508
#Does not prevent JS leaks of the page close event.
#https://developer.mozilla.org/en-US/docs/Web/Events/beforeunload
#echo -e "user_pref(\"dom.disable_beforeunload\",    true);" >> $USER_JS

#PREF: Disable Downloading on Desktop
#CIS 2.3.2
echo -e "user_pref(\"browser.download.folderList\",			2);" >> $USER_JS

#PREF: Always ask the user where to download
#https://developer.mozilla.org/en/Download_Manager_preferences (obsolete)
echo -e "user_pref(\"browser.download.useDownloadDir\",			false);" >> $USER_JS

#PREF: Disable the "new tab page" feature and show a blank tab instead
#https://wiki.mozilla.org/Privacy/Reviews/New_Tab
#https://support.mozilla.org/en-US/kb/new-tab-page-show-hide-and-customize-top-sites#w_how-do-i-turn-the-new-tab-page-off
echo -e "user_pref(\"browser.newtabpage.enabled\",				false);" >> $USER_JS
echo -e "user_pref(\"browser.newtab.url\",					\"about:blank\");" >> $USER_JS

#PREF: Disable new tab tile ads & preload
#http://www.thewindowsclub.com/disable-remove-ad-tiles-from-firefox
#http://forums.mozillazine.org/viewtopic.php?p=13876331#p13876331
#https://wiki.mozilla.org/Tiles/Technical_Documentation#Ping
#https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-source
#https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-ping
#TODO: deprecated? not in DXR, some dead links
echo -e "user_pref(\"browser.newtabpage.enhanced\",			false);" >> $USER_JS
echo -e "user_pref(\"browser.newtab.preload\",				false);" >> $USER_JS
echo -e "user_pref(\"browser.newtabpage.directory.ping\",			\"\");" >> $USER_JS
echo -e "user_pref(\"browser.newtabpage.directory.source\",		\"data:text/plain,{}\");" >> $USER_JS

#PREF: Enable Auto Notification of Outdated Plugins (Firefox < 50)
#https://wiki.mozilla.org/Firefox3.6/Plugin_Update_Awareness_Security_Review
#CIS Version 1.2.0 October 21st, 2011 2.1.2
#https://hg.mozilla.org/mozilla-central/rev/304560
echo -e "user_pref(\"plugins.update.notifyUser\",				true);" >> $USER_JS


#PREF: Force Punycode for Internationalized Domain Names
#http://kb.mozillazine.org/Network.IDN_show_punycode
#https://www.xudongz.com/blog/2017/idn-phishing/
#https://wiki.mozilla.org/IDN_Display_Algorithm
#https://en.wikipedia.org/wiki/IDN_homograph_attack
#https://www.mozilla.org/en-US/security/advisories/mfsa2017-02/
#CIS Mozilla Firefox 24 ESR v1.0.0 - 3.6
echo -e "user_pref(\"network.IDN_show_punycode\",				true);" >> $USER_JS

#PREF: Disable inline autocomplete in URL bar
#http://kb.mozillazine.org/Inline_autocomplete
echo -e "user_pref(\"browser.urlbar.autoFill\",				false);" >> $USER_JS
echo -e "user_pref(\"browser.urlbar.autoFill.typed\",			false);" >> $USER_JS

#PREF: Disable CSS :visited selectors
#https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/
#https://dbaron.org/mozilla/visited-privacy
echo -e "user_pref(\"layout.css.visited_links_enabled\",			false);" >> $USER_JS

#PREF: Disable URL bar autocomplete and history/bookmarks suggestions dropdown
#http://kb.mozillazine.org/Disabling_autocomplete_-_Firefox#Firefox_3.5
echo -e "user_pref(\"browser.urlbar.autocomplete.enabled\",		false);" >> $USER_JS

#PREF: Do not check if Firefox is the default browser
echo -e "user_pref(\"browser.shell.checkDefaultBrowser\",			false);" >> $USER_JS

#PREF: When password manager is enabled, lock the password storage periodically
#CIS Version 1.2.0 October 21st, 2011 2.5.3 Disable Prompting for Credential Storage
echo -e "user_pref(\"security.ask_for_password\",				2);" >> $USER_JS

#PREF: Lock the password storage every 1 minutes (default: 30)
echo -e "user_pref(\"security.password_lifetime\",				1);" >> $USER_JS

#PREF: Display a notification bar when websites offer data for offline use
#http://kb.mozillazine.org/Browser.offline-apps.notify
echo -e "user_pref(\"browser.offline-apps.notify\",			true);" >> $USER_JS

#PREF: Enable HSTS preload list (pre-set HSTS sites list provided by Mozilla)
#https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
#https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
#https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
echo -e "user_pref(\"network.stricttransportsecurity.preloadlist\",	true);" >> $USER_JS

#PREF: Enable Online Certificate Status Protocol
#https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol
#https://www.imperialviolet.org/2014/04/19/revchecking.html
#https://www.maikel.pro/blog/current-state-certificate-revocation-crls-ocsp/
#https://wiki.mozilla.org/CA:RevocationPlan
#https://wiki.mozilla.org/CA:ImprovingRevocation
#https://wiki.mozilla.org/CA:OCSP-HardFail
#https://news.netcraft.com/archives/2014/04/24/certificate-revocation-why-browsers-remain-affected-by-heartbleed.html
#https://news.netcraft.com/archives/2013/04/16/certificate-revocation-and-the-performance-of-ocsp.html
#NOTICE: OCSP leaks your IP and domains you visit to the CA when OCSP Stapling is not available on visited host
#NOTICE: OCSP is vulnerable to replay attacks when nonce is not configured on the OCSP responder
#NOTICE: OCSP adds latency (performance)
#NOTICE: Short-lived certificates are not checked for revocation (security.pki.cert_short_lifetime_in_days, default:10)
#CIS Version 1.2.0 October 21st, 2011 2.2.4
echo -e "user_pref(\"security.OCSP.enabled\",				1);" >> $USER_JS

#PREF: Enable OCSP Stapling support
#https://en.wikipedia.org/wiki/OCSP_stapling
#https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
#https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx
echo -e "user_pref(\"security.ssl.enable_ocsp_stapling\",			true);" >> $USER_JS

#PREF: Enable OCSP Must-Staple support (Firefox >= 45)
#https://blog.mozilla.org/security/2015/11/23/improving-revocation-ocsp-must-staple-and-short-lived-certificates/
#https://www.entrust.com/ocsp-must-staple/
#https://github.com/schomery/privacy-settings/issues/40
#NOTICE: Firefox falls back on plain OCSP when must-staple is not configured on the host certificate
echo -e "user_pref(\"security.ssl.enable_ocsp_must_staple\",		true);" >> $USER_JS

#PREF: Require a valid OCSP response for OCSP enabled certificates
#https://groups.google.com/forum/#!topic/mozilla.dev.security/n1G-N2-HTVA
#Disabling this will make OCSP bypassable by MitM attacks suppressing OCSP responses
#NOTICE: `security.OCSP.require` will make the connection fail when the OCSP responder is unavailable
#NOTICE: `security.OCSP.require` is known to break browsing on some [captive portals](https://en.wikipedia.org/wiki/Captive_portal)
echo -e "user_pref(\"security.OCSP.require\",				true);" >> $USER_JS

#PREF: Disable TLS Session Tickets
#https://www.blackhat.com/us-13/briefings.html#NextGen
#https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-Slides.pdf
#https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-WP.pdf
#https://bugzilla.mozilla.org/show_bug.cgi?id=917049
#https://bugzilla.mozilla.org/show_bug.cgi?id=967977
echo -e "user_pref(\"security.ssl.disable_session_identifiers\",		true);" >> $USER_JS

#PREF: Only allow TLS 1.[0-3]
#http://kb.mozillazine.org/Security.tls.version.*
#1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
#2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
echo -e "user_pref(\"security.tls.version.min\",				1);" >> $USER_JS
echo -e "user_pref(\"security.tls.version.max\",				4);" >> $USER_JS

#PREF: Disable insecure TLS version fallback
#https://bugzilla.mozilla.org/show_bug.cgi?id=1084025
#https://github.com/pyllyukko/$USER_JS/pull/206#issuecomment-280229645
echo -e "user_pref(\"security.tls.version.fallback-limit\",		3);" >> $USER_JS

#PREF: Enfore Public Key Pinning
#https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
#https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning
#"2. Strict. Pinning is always enforced."
echo -e "user_pref(\"security.cert_pinning.enforcement_level\",		2);" >> $USER_JS

#PREF: Disallow SHA-1
#https://bugzilla.mozilla.org/show_bug.cgi?id=1302140
#https://shattered.io/
echo -e "user_pref(\"security.pki.sha1_enforcement_level\",		1);" >> $USER_JS

#PREF: Warn the user when server doesn't support RFC 5746 (\"safe" renegotiation)
#https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
#https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
echo -e "user_pref(\"security.ssl.treat_unsafe_negotiation_as_broken\",	true);" >> $USER_JS

#PREF: Disallow connection to servers not supporting safe renegotiation (disabled)
#https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
#https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
#TODO: `security.ssl.require_safe_negotiation` is more secure but makes browsing next to impossible (2012-2014-... - `ssl_error_unsafe_negotiation` errors), so is left disabled
#echo -e "user_pref(\"security.ssl.require_safe_negotiation\",		true);" >> $USER_JS

#PREF: Disable automatic reporting of TLS connection errors
#https://support.mozilla.org/en-US/kb/certificate-pinning-reports
#we could also disable security.ssl.errorReporting.enabled, but I think it's
#good to leave the option to report potentially malicious sites if the user
#chooses to do so.
#you can test this at https://pinningtest.appspot.com/
echo -e "user_pref(\"security.ssl.errorReporting.automatic\",		false);" >> $USER_JS

#PREF: Pre-populate the current URL but do not pre-fetch the certificate in the "Add Security Exception" dialog
#http://kb.mozillazine.org/Browser.ssl_override_behavior
#https://github.com/pyllyukko/$USER_JS/issues/210
echo -e "user_pref(\"browser.ssl_override_behavior\",			1);" >> $USER_JS

#PREF: Disable null ciphers
echo -e "user_pref(\"security.ssl3.rsa_null_sha\",				false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.rsa_null_md5\",				false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_rsa_null_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_ecdsa_null_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdh_rsa_null_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdh_ecdsa_null_sha\",			false);" >> $USER_JS

#PREF: Disable SEED cipher
#https://en.wikipedia.org/wiki/SEED
echo -e "user_pref(\"security.ssl3.rsa_seed_sha\",				false);" >> $USER_JS

#PREF: Disable 40/56/128-bit ciphers
#40-bit ciphers
echo -e "user_pref(\"security.ssl3.rsa_rc4_40_md5\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.rsa_rc2_40_md5\",			false);" >> $USER_JS
#56-bit ciphers
echo -e "user_pref(\"security.ssl3.rsa_1024_rc4_56_sha\",			false);" >> $USER_JS
#128-bit ciphers
echo -e "user_pref(\"security.ssl3.rsa_camellia_128_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_rsa_aes_128_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_ecdsa_aes_128_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdh_rsa_aes_128_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdh_ecdsa_aes_128_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.dhe_rsa_camellia_128_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.dhe_rsa_aes_128_sha\",			false);" >> $USER_JS

#PREF: Disable RC4
#https://developer.mozilla.org/en-US/Firefox/Releases/38#Security
#https://bugzilla.mozilla.org/show_bug.cgi?id=1138882
#https://rc4.io/
#https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2566
echo -e "user_pref(\"security.ssl3.ecdh_ecdsa_rc4_128_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdh_rsa_rc4_128_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_ecdsa_rc4_128_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_rsa_rc4_128_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.rsa_rc4_128_md5\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.rsa_rc4_128_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.tls.unrestricted_rc4_fallback\",		false);" >> $USER_JS

#PREF: Disable 3DES (effective key size is < 128)
#https://en.wikipedia.org/wiki/3des#Security
#http://en.citizendium.org/wiki/Meet-in-the-middle_attack
#http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
echo -e "user_pref(\"security.ssl3.dhe_dss_des_ede3_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.dhe_rsa_des_ede3_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdh_ecdsa_des_ede3_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdh_rsa_des_ede3_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_ecdsa_des_ede3_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_rsa_des_ede3_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.rsa_des_ede3_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.rsa_fips_des_ede3_sha\",		false);" >> $USER_JS

#PREF: Disable ciphers with ECDH (non-ephemeral)
echo -e "user_pref(\"security.ssl3.ecdh_rsa_aes_256_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdh_ecdsa_aes_256_sha\",		false);" >> $USER_JS

#PREF: Disable 256 bits ciphers without PFS
echo -e "user_pref(\"security.ssl3.rsa_camellia_256_sha\",			false);" >> $USER_JS

#PREF: Enable ciphers with ECDHE and key size > 128bits
echo -e "user_pref(\"security.ssl3.ecdhe_rsa_aes_256_sha\",		true);" >> $USER_JS #0xc014
echo -e "user_pref(\"security.ssl3.ecdhe_ecdsa_aes_256_sha\",		true);" >> $USER_JS #0xc00a

#PREF: Enable GCM ciphers (TLSv1.2 only)
#https://en.wikipedia.org/wiki/Galois/Counter_Mode
echo -e "user_pref(\"security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256\",	true);" >> $USER_JS #0xc02b
echo -e "user_pref(\"security.ssl3.ecdhe_rsa_aes_128_gcm_sha256\",		true);" >> $USER_JS #0xc02f

#PREF: Enable ChaCha20 and Poly1305 (Firefox >= 47)
#https://www.mozilla.org/en-US/firefox/47.0/releasenotes/
#https://tools.ietf.org/html/rfc7905
#https://bugzilla.mozilla.org/show_bug.cgi?id=917571
#https://bugzilla.mozilla.org/show_bug.cgi?id=1247860
#https://cr.yp.to/chacha.html
echo -e "user_pref(\"security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256\",	true);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256\",	true);" >> $USER_JS

#PREF: Disable ciphers susceptible to the logjam attack
#https://weakdh.org/
echo -e "user_pref(\"security.ssl3.dhe_rsa_camellia_256_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.dhe_rsa_aes_256_sha\",			false);" >> $USER_JS

#PREF: Disable ciphers with DSA (max 1024 bits)
echo -e "user_pref(\"security.ssl3.dhe_dss_aes_128_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.dhe_dss_aes_256_sha\",			false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.dhe_dss_camellia_128_sha\",		false);" >> $USER_JS
echo -e "user_pref(\"security.ssl3.dhe_dss_camellia_256_sha\",		false);" >> $USER_JS

#PREF: Fallbacks due compatibility reasons
echo -e "user_pref(\"security.ssl3.rsa_aes_256_sha\",			true);" >> $USER_JS #0x35
echo -e "user_pref(\"security.ssl3.rsa_aes_128_sha\",			true);" >> $USER_JS #0x2f
