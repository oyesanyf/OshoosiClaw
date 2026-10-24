// // import "androguard"

// rule Android_DeathRing (Disabled: vacuous condition without evaluatable strings/modules)
// { (Disabled: vacuous condition without evaluatable strings/modules)
// 	meta: (Disabled: vacuous condition without evaluatable strings/modules)
// 		author = "Jacob Soo Lead Re" (Disabled: vacuous condition without evaluatable strings/modules)
// 		date = "06-June-2016" (Disabled: vacuous condition without evaluatable strings/modules)
// 		description = "DeathRing is a Chinese Trojan that is pre-installed on a number of smartphones most popular in Asian and African countries. Detection volumes are moderate, though we consider this a concerning threat given its pre-loaded nature and the fact that we are actively seeing detections of it around the world." (Disabled: vacuous condition without evaluatable strings/modules)
// 		source = "https://blog.lookout.com/blog/2014/12/04/deathring/" (Disabled: vacuous condition without evaluatable strings/modules)
//  (Disabled: vacuous condition without evaluatable strings/modules)
// 	condition: (Disabled: vacuous condition without evaluatable strings/modules)
// 		androguard.service(/MainOsService/i) and (Disabled by Oshoosi Hardener)
//         androguard.receiver(/ApkUninstallReceiver/i) (Disabled by Oshoosi Hardener)
// } (Disabled: vacuous condition without evaluatable strings/modules)
