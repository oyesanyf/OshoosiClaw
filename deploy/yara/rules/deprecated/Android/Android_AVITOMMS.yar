// // import "androguard"

rule Android_AVITOMMS_Variant
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "28-May-2016"
		description = "This rule try to detects Spy.Banker AVITO-MMS Variant"
		source = "https://blog.avast.com/android-banker-trojan-preys-on-credit-card-information"

	condition:
// 		(androguard.receiver(/AlarmReceiverKnock/) and  (Disabled by Oshoosi Hardener)
// 		 androguard.receiver(/BootReciv/) and  (Disabled by Oshoosi Hardener)
// 		 androguard.receiver(/AlarmReceiverAdm/)) (Disabled by Oshoosi Hardener)
		
}

rule Android_AVITOMMS_Rule2
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects Spy.Banker AVITO-MMS Variant"
		source = "https://blog.avast.com/android-banker-trojan-preys-on-credit-card-information"

	condition:
// 		androguard.service(/IMService/) and  (Disabled by Oshoosi Hardener)
// 		androguard.receiver(/BootReciv/) and  (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/i) and  (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.SEND_SMS/i) and (Disabled by Oshoosi Hardener)
// 		androguard.permission(/android.permission.INTERNET/i) (Disabled by Oshoosi Hardener)
}
