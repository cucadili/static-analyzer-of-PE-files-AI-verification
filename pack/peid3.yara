
rule EncryptPEV22004616V22006630WFS
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin03Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

condition:
		$a0
}
	
	
rule PseudoSigner02PEPack099
{
strings:
		$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A }

condition:
		$a0 at entrypoint
}
	
	
rule D1S1Gv11betaD1N
{
strings:
		$a0 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 0A 00 00 00 18 00 00 80 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 02 00 00 00 88 00 00 80 38 00 00 80 96 00 00 80 50 00 00 80 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 00 00 68 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 00 00 78 00 00 00 B0 ?? ?? 00 10 00 00 00 00 00 00 00 00 00 00 00 C0 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 06 00 44 00 56 00 43 00 4C 00 41 00 4C 00 0B 00 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F 00 00 00 }

condition:
		$a0
}
	
	
rule EnigmaProtector1XSukhovVladimirSergeNMarkin
{
strings:
		$a0 = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 }
	$a1 = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 52 65 67 43 6C 6F 73 65 4B 65 79 00 00 00 53 79 73 46 72 65 65 53 74 72 69 6E 67 00 00 00 43 72 65 61 74 65 46 6F 6E 74 41 00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 00 00 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule UPXHiTv001
{
strings:
		$a0 = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }

condition:
		$a0
}
	
	
rule CryptoLock202EngRyanThian
{
strings:
		$a0 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
	$a1 = { 60 BE ?? 90 40 00 8D BE ?? ?? FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule DxPackV086Dxd
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMicrosoftVisualC60
{
strings:
		$a0 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 }
	$a1 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE EB 02 CD 20 57 EB 02 CD 20 5A 88 10 EB 02 CD 20 40 E8 02 00 00 00 C5 62 5A 4E E8 01 00 00 00 43 5A 2B DB 3B F3 75 B1 C1 F3 0D 92 B8 DC 0C 4E 0D B7 F7 0A 39 F4 B5 ?? ?? 36 FF 45 D9 FA FB FE FD FE CD 6B FE 82 0D 28 F3 B6 A6 A0 71 1F BA 92 9C EE DA FE 0D 47 DB 09 AE DF E3 F6 50 E4 12 9E C8 EC FB 4D EA 77 C9 03 75 E0 D2 D6 E5 E2 8B 41 B6 41 FA 70 B0 A0 AB F9 B5 C0 BF ED 78 25 CB 96 E5 A8 A7 AA A0 DC 5F 73 9D 14 F0 B5 6A 87 B7 3B E5 6D 77 B2 45 8C B9 96 95 A0 DC A2 1E 9C 9B 11 93 08 83 9B F8 9E 0A 8E 10 F7 85 }
	$a2 = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
	$a3 = { C1 CE 10 C1 F6 0F 68 00 ?? ?? 00 2B FA 5B 23 F9 8D 15 80 ?? ?? 00 E8 01 00 00 00 B6 5E 0B }
	$a4 = { D1 E9 03 C0 68 80 ?? ?? 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E }
	$a5 = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
	$a6 = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
	$a7 = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 ?? ?? 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8 }
	$a8 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? ?? BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }
	$a9 = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint or $a4 at entrypoint or $a5 at entrypoint or $a6 at entrypoint or $a7 at entrypoint or $a8 at entrypoint or $a9 at entrypoint
}
	
	
rule MicrosoftVisualStudioNET
{
strings:
		$a0 = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule TPPpackclane
{
strings:
		$a0 = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8 }

condition:
		$a0
}
	
	
rule FSG110EngdulekxtMicrosoftVisualC60
{
strings:
		$a0 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall24x25xJititSoftware
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? BD ?? ?? ?? ?? 03 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV119aPlib043ap0xSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 }

condition:
		$a0 at entrypoint
}
	
	
rule LocklessIntroPack
{
strings:
		$a0 = { 2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }

condition:
		$a0 at entrypoint
}
	
	
rule ProActivateV10XTurboPowerSoftwareCompanySignbyfly
{
strings:
		$a0 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? ?? 90 90 90 90 90 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? 83 C0 05 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0D 00 00 00 E8 85 E2 FF FF 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 7A 81 3D ?? ?? ?? ?? 43 52 43 33 75 6E 81 3D ?? ?? ?? ?? 32 40 7E 7E 75 62 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 56 81 3D ?? ?? ?? ?? 43 52 43 33 75 4A 81 3D ?? ?? ?? ?? 32 40 7E 7E 75 3E 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 32 81 3D ?? ?? ?? ?? 43 52 43 33 }

condition:
		$a0 at entrypoint
}
	
	
rule PEArmor046Hying
{
strings:
		$a0 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorv13CGSoftLabs
{
strings:
		$a0 = { 45 78 50 72 2D 76 2E 31 2E 33 2E }

condition:
		$a0
}
	
	
rule MSLRHV031emadicius
{
strings:
		$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv184
{
strings:
		$a0 = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

condition:
		$a0 at entrypoint
}
	
	
rule Anti007V25V26NsPacKPrivate
{
strings:
		$a0 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 }

condition:
		$a0 at entrypoint
}
	
	
rule WinUpackv030betaByDwingh
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 }

condition:
		$a0
}
	
	
rule WiseInstallerStub
{
strings:
		$a0 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF }
	$a1 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF 89 45 FC 0F 84 7B 01 00 00 8D 85 90 FC FF FF 50 56 FF 15 28 20 40 00 8D 85 98 FE FF FF 50 53 8D 85 90 FC FF FF 68 10 30 40 00 50 FF 15 24 20 40 00 53 68 80 00 00 00 6A 02 53 53 8D 85 98 FE FF FF 68 00 00 00 40 50 FF D7 83 F8 FF 89 45 F4 0F 84 2F 01 00 00 53 53 53 6A 02 53 FF 75 FC FF 15 00 20 40 00 53 53 53 6A 04 50 89 45 F8 FF 15 1C 20 40 00 8B F8 C7 45 FC 01 00 00 00 8D 47 01 8B 08 81 F9 4D 5A 9A 00 74 08 81 F9 4D 5A 90 00 75 06 80 78 04 03 74 0D FF 45 FC 40 81 7D FC 00 80 00 00 7C DB 8D 4D F0 53 51 68 }
	$a2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 }
	$a3 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 75 09 47 80 3F 20 74 FA 89 7D ?? 53 FF 15 ?? 40 40 00 80 3F 2F 89 45 ?? 75 ?? 8A 47 01 3C 53 74 04 3C 73 75 06 89 35 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 or $a3
}
	
	
rule AnskyaNTPackerGeneratorAnskya
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50 E8 71 FB FF FF 8B D8 85 DB 74 2F 53 A1 14 31 00 10 50 E8 97 FB FF FF 85 C0 74 1F 53 A1 14 31 00 10 50 E8 5F FB FF FF 85 C0 74 0F 50 E8 5D FB FF FF 85 C0 74 05 E8 70 }
	$a1 = { 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50 E8 71 FB FF FF 8B D8 85 DB 74 2F 53 A1 14 31 00 10 50 E8 97 FB FF FF 85 C0 74 1F 53 A1 14 31 00 10 50 E8 5F FB FF FF 85 C0 74 0F 50 E8 5D FB FF FF 85 C0 74 05 E8 70 FC FF FF 5B E8 F2 F6 FF FF 00 00 48 45 41 52 54 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule EXECryptor2021protectedIATwwwstrongbitcom
{
strings:
		$a0 = { A4 ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? 94 ?? ?? ?? D8 ?? ?? ?? 00 00 00 00 FF FF FF FF B8 ?? ?? ?? D4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack14byNorthStarLiuXingPing
{
strings:
		$a0 = { 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 }

condition:
		$a0
}
	
	
rule FSGv110EngbartxtWatcomCCEXE
{
strings:
		$a0 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }

condition:
		$a0 at entrypoint
}
	
	
rule Berio200betah
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 01 74 01 }

condition:
		$a0 at entrypoint
}
	
	
rule AcidCrypt
{
strings:
		$a0 = { 60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
	$a1 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule LauncherGenerator103
{
strings:
		$a0 = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 }

condition:
		$a0
}
	
	
rule WinKript10MrCrimsonh
{
strings:
		$a0 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 83 C0 08 EB D5 61 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule USSRV031SpiritSTSignbyfly
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 2E 55 53 53 52 00 00 00 00 10 00 00 ?? ?? ?? ?? 00 10 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule CrunchPEv20xx
{
strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 55 BB ?? ?? ?? ?? 03 DD 53 64 67 FF 36 ?? ?? 64 67 89 26 }

condition:
		$a0 at entrypoint
}
	
	
rule PackanoidArkanoid
{
strings:
		$a0 = { BF 00 10 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 }

condition:
		$a0 at entrypoint
}
	
	
rule DAEMONProtectv067
{
strings:
		$a0 = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61 }

condition:
		$a0 at entrypoint
}
	
	
rule MEW11SEv12NorthfoxHCC
{
strings:
		$a0 = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SymantecCv210v400orZortechCv30r1
{
strings:
		$a0 = { FA FC B8 ?? ?? 8E D8 }

condition:
		$a0 at entrypoint
}
	
	
rule EmbedPEV100V124cyclotron
{
strings:
		$a0 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E }

condition:
		$a0 at entrypoint
}
	
	
rule VProtectorV10Avcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 8A 8E 40 00 68 C6 8E 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

condition:
		$a0 at entrypoint
}
	
	
rule EncryptPE2200481022005314WFS
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A }

condition:
		$a0 at entrypoint
}
	
	
rule UPXScramblerbyGurueXe
{
strings:
		$a0 = { 66 C7 05 ?? ?? ?? ?? 75 07 E9 ?? FE FF FF 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 00 ?? ?? 00 }

condition:
		$a0
}
	
	
rule EmbedPEV1Xcyclotron
{
strings:
		$a0 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 ?? ?? 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule FileAnalyzerExtendedDatafileVersion
{
strings:
		$a0 = { 23 03 45 58 54 44 ?? ?? 3A 03 }

condition:
		$a0
}
	
	
rule NsPack14Liuxingping
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftResourceCursorsfile
{
strings:
		$a0 = { 00 00 02 00 01 00 20 20 00 00 ?? 00 ?? 00 E8 02 00 00 16 }

condition:
		$a0
}
	
	
rule VxTrivial46
{
strings:
		$a0 = { B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule STUDRC410JamieEditionScanTimeUnDetectablebyMarjinZ
{
strings:
		$a0 = { 68 2C 11 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00 37 BB 71 EC A4 E1 98 4C 9B FE 8F 0F FA 6A 07 F6 00 00 00 00 00 00 01 00 00 00 20 20 46 6F 72 20 73 74 75 64 00 20 54 6F 00 00 00 00 06 00 00 00 CC 1A 40 00 07 00 00 00 D4 }
	$a1 = { 68 2C 11 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00 37 BB 71 EC A4 E1 98 4C 9B FE 8F 0F FA 6A 07 F6 00 00 00 00 00 00 01 00 00 00 20 20 46 6F 72 20 73 74 75 64 00 20 54 6F 00 00 00 00 06 00 00 00 CC 1A 40 00 07 00 00 00 D4 18 40 00 07 00 00 00 7C 18 40 00 07 00 00 00 2C 18 40 00 07 00 00 00 E0 17 40 00 56 42 35 21 F0 1F 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 7E 00 00 00 00 00 00 00 00 00 00 00 00 00 0A 00 09 04 00 00 00 00 00 00 E8 13 40 00 F4 13 40 00 00 F0 30 00 00 FF FF FF 08 00 00 00 01 00 00 00 00 00 00 00 E9 00 00 00 04 11 40 00 04 11 40 00 C8 10 40 00 78 00 00 00 7C 00 00 00 81 00 00 00 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 61 61 00 53 74 75 64 00 00 73 74 75 64 00 00 01 00 01 00 30 16 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 B4 16 40 00 10 30 40 00 07 00 00 00 24 12 40 00 0E 00 20 00 00 00 00 00 1C 9E 21 00 EC 11 40 00 5C 10 40 00 E4 1A 40 00 2C 34 40 00 68 17 40 00 58 17 40 00 78 17 40 00 8C 17 40 00 8C 10 40 00 62 10 40 00 92 10 40 00 F8 1A 40 00 24 19 40 00 98 10 40 00 9E 10 40 00 77 04 18 FF 04 1C FF 05 00 00 24 01 00 0D 14 00 78 1C 40 00 48 21 40 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule CopyMinderMicrocosmLtdSignbyfly
{
strings:
		$a0 = { 83 25 ?? ?? ?? ?? EF 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 }

condition:
		$a0 at entrypoint
}
	
	
rule VxSonikYouth
{
strings:
		$a0 = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01Anorganix
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv305c4ExtractablePasswordchecking
{
strings:
		$a0 = { 03 05 80 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule PESHiELDv0251
{
strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote10betaSpyInstructor
{
strings:
		$a0 = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 }
	$a1 = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 66 8B 41 06 89 54 24 14 8D 68 FF 85 ED 7C 37 33 C0 8B 4C 24 14 8D 04 80 8B 4C C1 08 85 C9 74 1A 8B C1 33 D2 F7 F6 85 D2 75 04 03 F9 EB 0C 8B C1 33 D2 F7 F6 40 0F AF C6 03 F8 43 8B C3 25 FF FF 00 00 3B C5 7E CB 8B C7 5F 5E 5D 5B C3 90 90 90 90 90 90 90 90 90 90 90 90 55 8B EC 6A FF 68 50 22 60 00 64 A1 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule SPLayerv008
{
strings:
		$a0 = { 8D 40 00 B9 ?? ?? ?? ?? 6A ?? 58 C0 0C ?? ?? 48 ?? ?? 66 13 F0 91 3B D9 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

condition:
		$a0
}
	
	
rule SetupFactoryv6003SetupLauncher
{
strings:
		$a0 = { 55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89 40 00 33 F6 56 E8 E0 00 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 E6 0F 00 00 FF 15 10 61 40 00 A3 40 8E 40 00 E8 A4 0E 00 00 A3 90 89 40 00 E8 4D 0C 00 00 E8 8F 0B 00 00 E8 22 FE FF FF 89 75 D0 8D 45 A4 50 FF 15 0C 61 40 00 E8 20 0B 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 08 61 40 00 50 E8 5A E9 FF FF 89 45 A0 50 E8 10 FE FF FF 8B 45 }

condition:
		$a0
}
	
	
rule CrypKeyV61XDLLCrypKeyCanadaInc
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8 }

condition:
		$a0 at entrypoint
}
	
	
rule VcAsmProtectorVcAsm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule ENIGMAProtectorV11V12SukhovVladimir
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 }

condition:
		$a0 at entrypoint
}
	
	
rule PEDiminisherv01
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 }
	$a1 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule SOFTWrapperforWin9xNTEvaluationVersion
{
strings:
		$a0 = { E8 00 00 00 00 5D 8B C5 2D ?? ?? ?? 00 50 81 ED 05 00 00 00 8B C5 2B 85 03 0F 00 00 89 85 03 0F 00 00 8B F0 03 B5 0B 0F 00 00 8B F8 03 BD 07 0F 00 00 83 7F 0C 00 74 2B 56 57 8B 7F 10 03 F8 8B 76 10 03 F0 83 3F 00 74 0C 8B 1E 89 1F 83 C6 04 83 C7 04 EB EF }
	$a1 = { E8 00 00 00 00 5D 8B C5 2D ?? ?? ?? 00 50 81 ED 05 00 00 00 8B C5 2B 85 03 0F 00 00 89 85 03 0F 00 00 8B F0 03 B5 0B 0F 00 00 8B F8 03 BD 07 0F 00 00 83 7F 0C 00 74 2B 56 57 8B 7F 10 03 F8 8B 76 10 03 F0 83 3F 00 74 0C 8B 1E 89 1F 83 C6 04 83 C7 04 EB EF 5F 5E 83 C6 14 83 C7 14 EB D3 00 00 00 00 8B F5 81 C6 0D 0A 00 00 B9 0C 00 00 00 8B 85 03 0F 00 00 01 46 02 83 C6 06 E2 F8 E8 06 08 00 00 68 00 01 00 00 8D 85 DD 0D 00 00 50 6A 00 E8 95 09 00 00 8B B5 03 0F 00 00 66 81 3E 4D 5A 75 33 03 76 3C 81 3E 50 45 00 00 75 28 8B 46 28 03 85 03 0F 00 00 3B C5 74 1B 6A 30 E8 99 09 00 00 6A 30 8D 85 DD 0D 00 00 50 8D 85 2B 0F 00 00 E9 55 03 00 00 66 8B 85 9D 0A 00 00 F6 C4 80 74 31 E8 6A 07 00 00 0B C0 75 23 6A 40 E8 69 09 00 00 6A 40 8D 85 DD 0D 00 00 50 8B 9D 17 0F }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MicrosoftC19881989
{
strings:
		$a0 = { B4 30 CD 21 3C 02 73 ?? CD 20 BF ?? ?? 8B ?? ?? ?? 2B F7 81 ?? ?? ?? 72 }

condition:
		$a0 at entrypoint
}
	
	
rule Morphinev27Holy_FatherRatter29Ah
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule byCentralPointSoftware
{
strings:
		$a0 = { 50 51 52 56 57 8B EB 1E 2E }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack31byNorthStarLiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov200
{
strings:
		$a0 = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov201
{
strings:
		$a0 = { 55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectSKE2122exeAlexeySolodovnikovh
{
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a1 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C }
	$a2 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }

condition:
		$a0 or $a1 or $a2
}
	
	
rule ElicenseSystemV4000ViaTechInc
{
strings:
		$a0 = { 00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00 }

condition:
		$a0
}
	
	
rule NSISInstallerNullSoft
{
strings:
		$a0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 80 72 40 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv032BetaPatchSignbyhot_UNP
{
strings:
		$a0 = { BE 88 01 ?? ?? AD 50 ?? AD 91 F3 A5 }

condition:
		$a0
}
	
	
rule MicrosoftVisualBasicv50
{
strings:
		$a0 = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SentinelSuperProAutomaticProtection641Safenet
{
strings:
		$a0 = { A1 ?? ?? ?? ?? 55 8B ?? ?? ?? 85 C0 74 ?? 85 ED 75 ?? A1 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 55 51 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 15 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 01 00 00 00 5D C2 0C 00 }

condition:
		$a0
}
	
	
rule PEXv099
{
strings:
		$a0 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }

condition:
		$a0 at entrypoint
}
	
	
rule ANDpakk2018byDmitryquotANDquotAndreev
{
strings:
		$a0 = { FC BE D4 00 40 00 BF 00 ?? ?? 00 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }

condition:
		$a0 at entrypoint
}
	
	
rule IMPPacker10MahdiHezavehiIMPOSTER
{
strings:
		$a0 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
	$a1 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

condition:
		$a0 or $a1
}
	
	
rule PEProtectv09
{
strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }

condition:
		$a0 at entrypoint
}
	
	
rule nbuildv10soft
{
strings:
		$a0 = { B9 ?? ?? BB ?? ?? C0 ?? ?? 80 ?? ?? 43 E2 }

condition:
		$a0 at entrypoint
}
	
	
rule IProtect10FxSubdllmodebyFuXdas
{
strings:
		$a0 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 53 75 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED B6 13 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 A8 13 40 00 }
	$a1 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 53 75 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED B6 13 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 A8 13 40 00 8D 85 81 13 40 00 50 FF B5 A8 13 40 00 E8 92 00 00 00 0B C0 74 13 89 85 A4 13 40 00 8D 85 8E 13 40 00 50 FF 95 A4 13 40 00 8B 85 AC 13 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 B5 FA FF FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RECC0dedbyROSE
{
strings:
		$a0 = { 06 1E 0E 0E 07 1F B4 30 CD 21 86 E0 3D 00 03 73 ?? CD 20 EB }

condition:
		$a0 at entrypoint
}
	
	
rule MSVisualCv8DLLhsmallsig2
{
strings:
		$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01 }

condition:
		$a0 at entrypoint
}
	
	
rule MSVisualCv8DLLhsmallsig1
{
strings:
		$a0 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 ?? ?? ?? FF 5D E9 D6 FE FF FF CC CC CC CC CC }

condition:
		$a0 at entrypoint
}
	
	
rule EncapsulatedPostscriptgraphicsfilev20EPSF12
{
strings:
		$a0 = { 25 21 50 53 2D 41 64 6F 62 65 2D 32 2E 30 20 45 50 53 46 2D 31 2E 32 }

condition:
		$a0
}
	
	
rule MicroJoiner11coban2k
{
strings:
		$a0 = { BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov301v350aSiliconRealmsToolworks
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 ?? 87 DB 7A F0 ?? ?? 61 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 ?? 8B 04 24 EB 03 7A 29 ?? C6 00 90 C3 ?? 70 F0 87 D2 71 07 ?? ?? 40 8B DB 7A 11 EB 08 ?? EB F7 EB C3 ?? 7A E9 70 DA 7B D1 71 F3 ?? 7B F3 71 D6 ?? 9D 61 83 ED 06 33 FF 47 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 EB 87 ?? 7A F0 ?? ?? 61 8B 9C BD B8 43 }

condition:
		$a0 at entrypoint
}
	
	
rule BladeJoinerv15
{
strings:
		$a0 = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack0280399relocatedimagebaseDelphiNETDLLorsomethingelseDwingh
{
strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 }

condition:
		$a0
}
	
	
rule beriav007publicWIPsymbionth
{
strings:
		$a0 = { 83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0 3B F5 74 37 8B 46 0C 3B C5 8B 3D 04 30 ?? ?? 89 2E 89 6E 04 89 6E 08 74 06 50 FF D7 89 6E 0C 8B 46 10 3B C5 74 06 50 FF D7 89 6E 10 8B 46 14 3B C5 74 0A 50 FF D7 89 6E 14 EB 02 33 F6 6A 10 55 89 35 A4 40 ?? ?? FF D3 8B F0 3B F5 74 09 E8 08 12 00 00 8B C6 EB 02 33 C0 8B 48 08 8B 51 04 8B 09 8B 35 30 30 ?? ?? A3 D4 43 ?? ?? 8B 00 03 D0 52 03 C8 51 FF D6 8B 3D 24 30 ?? ?? 50 FF D7 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv133Engdulekxt
{
strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF }
	$a1 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 9D 8B D6 5E AD 48 74 0A 79 02 AD 50 56 8B F2 97 EB 87 AD 93 5E 46 AD 97 56 FF 13 95 AC 84 C0 75 FB FE 0E 74 F0 79 05 46 AD 50 EB 09 FE 0E 0F 84 ?? ?? ?? FF 56 55 FF 53 04 AB EB E0 33 C9 41 FF 13 13 C9 FF 13 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 54 01 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 01 00 00 6F 01 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule yodasProtector10betaAshkbizDanehkar
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv13
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE }
	$a1 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE ?? 74 EF FE }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule FSGv12
{
strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv11
{
strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv10
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv4x
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 }

condition:
		$a0 at entrypoint
}
	
	
rule CRYPTVersion17cDismemberCOM
{
strings:
		$a0 = { 0E 17 9C 58 F6 C4 01 ?? ?? ?? ?? ?? B4 01 BE ?? ?? BF ?? ?? B9 ?? ?? 68 ?? ?? 68 ?? ?? 68 ?? ?? 57 F3 A4 C3 B0 02 E6 21 60 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv120EngdulekxtMicrosoftVisualC6070
{
strings:
		$a0 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA 73 8B CF 81 C2 96 44 EB 04 EB 02 CD 20 88 16 E8 02 00 00 00 44 A2 59 46 E8 01 00 00 00 AD 59 4B 80 C1 13 83 FB 00 75 B2 F7 D9 96 8F 80 4D 0C 4C 91 50 1C 0C 50 8A ?? ?? ?? 50 E9 34 16 50 4C 4C 0E 7E 9B 49 C6 32 02 3E 7E 7B 5E 8C C5 6B 50 3F 0E 0F 38 C8 95 18 D1 65 11 2C B8 87 28 C3 4C 0B 3C AC D9 2D 15 4E 8F 1C 40 4F 28 98 3E 10 C1 45 DB 8F 06 3F EC 48 61 4C 50 50 81 DF C3 20 34 84 10 10 0C 1F 68 DC FF 24 8C 4D 29 F5 1D 2C BF 74 CF F0 24 C0 08 2E 0C 0C 10 51 0C 91 10 10 81 16 D0 54 4B D7 42 C3 54 CB C9 4E }

condition:
		$a0 at entrypoint
}
	
	
rule nSPack2x3xNETNorthStarLiuXingPing
{
strings:
		$a0 = { FF 25 A4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a1 = { FF 25 A4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MinGWv32xmain
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 F4 40 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 8D 07 00 00 83 EC 04 E8 85 02 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 24 0C 8D 55 F4 89 54 24 08 C7 44 24 04 04 20 40 00 E8 02 07 00 00 A1 20 20 40 00 85 C0 74 76 A3 30 20 40 00 A1 F0 40 40 00 85 C0 74 1F 89 04 24 E8 C3 06 00 00 8B 1D 20 20 40 00 89 04 24 89 5C 24 04 E8 C1 06 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SuperDAT
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 F3 42 00 68 A4 BF 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 F2 42 00 33 D2 8A D4 89 15 60 42 43 00 8B C8 81 E1 FF 00 00 00 89 0D }

condition:
		$a0 at entrypoint
}
	
	
rule NsPackv37NorthStarh
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 8D ?? ?? ?? FF 80 39 01 0F 84 42 02 00 00 C6 01 01 8B C5 2B 85 ?? ?? ?? FF 89 85 ?? ?? ?? FF 01 85 ?? ?? ?? FF 8D B5 ?? ?? ?? FF 01 06 55 56 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? ?? FF 85 C0 0F 84 69 03 00 00 89 85 ?? ?? ?? FF E8 00 00 00 00 5B B9 67 03 00 00 03 D9 50 53 E8 B0 02 00 00 5E 5D 8B 36 8B FD 03 BD ?? ?? ?? FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 34 01 13 8B 33 03 7B 04 57 51 53 FF B5 ?? ?? ?? FF FF B5 ?? ?? ?? FF 8B D6 8B CF 8B 85 ?? ?? ?? FF 05 AA 05 00 00 FF D0 5B 59 5F 83 F9 00 74 05 83 C3 08 EB C7 68 00 80 00 00 6A 00 FF B5 ?? ?? ?? FF FF 95 ?? ?? ?? FF 8D B5 ?? ?? ?? FF 8B 4E 08 8D 56 10 8B 36 8B FE 83 F9 00 74 3F 8A 07 47 2C E8 3C 01 77 F7 8B 07 80 7A 01 00 74 14 8A 1A 38 1F 75 E9 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 EB 0A 8A 5F 04 86 C4 C1 C0 10 86 C4 2B C7 03 C6 89 07 83 C7 05 80 EB E8 8B C3 E2 C6 E8 3A 01 00 00 8D 8D }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv200alpha38
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F 00 50 57 56 FF D1 58 03 43 08 8B F8 8B 53 14 8B F0 8B 46 FC 83 C0 04 2B F0 89 56 08 8B 4B 10 89 4E 18 FF D7 89 85 BB 10 00 10 5E 5A 5F 59 5B 5D 9D FF E0 8B 80 BB 10 00 10 FF E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule SDProtector11xRandyLi
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeMicrosoftVisualCemadiciush
{
strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv103b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }

condition:
		$a0 at entrypoint
}
	
	
rule MEW11SE12
{
strings:
		$a0 = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule UpackV010V011DwingSignbyfly
{
strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 ?? F3 AB C1 E0 ?? B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C ?? 73 ?? B0 ?? 3C ?? 72 02 2C ?? 50 0F B6 5F FF C1 E3 ?? B3 ?? 8D 1C 5B 8D ?? ?? ?? ?? ?? ?? B0 ?? 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 }

condition:
		$a0 at entrypoint
}
	
	
rule TheGuardLibrary
{
strings:
		$a0 = { 50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3 }

condition:
		$a0 at entrypoint
}
	
	
rule LZEXEv091v100a1
{
strings:
		$a0 = { 06 0E 1F 8B ?? ?? ?? 8B F1 4E 89 F7 }

condition:
		$a0 at entrypoint
}
	
	
rule LZEXEv091v100a2
{
strings:
		$a0 = { BF ?? ?? 06 89 F9 0E 41 1F 8C CB 89 FE }

condition:
		$a0 at entrypoint
}
	
	
rule FreeCryptor01build001GlOFF
{
strings:
		$a0 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 68 26 ?? ?? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }

condition:
		$a0
}
	
	
rule PCGuardv405dv410dv415d
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule DingBoysPElockPhantasmv08
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }

condition:
		$a0 at entrypoint
}
	

	
	
rule RLPackV115V117LZMA430ap0xSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 83 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB 14 }

condition:
		$a0 at entrypoint
}
	
	
rule Unknownpacker06
{
strings:
		$a0 = { FA B8 ?? ?? BE ?? ?? 33 F0 0E 17 2E ?? ?? ?? BA ?? ?? 87 E6 5B 33 DC }

condition:
		$a0 at entrypoint
}
	
	
rule Unknownpacker05
{
strings:
		$a0 = { FA BB ?? ?? B9 ?? ?? 87 E5 87 27 03 E3 91 8A CB 80 E1 ?? D3 C4 91 33 E3 87 27 }

condition:
		$a0 at entrypoint
}
	
	
rule Unknownpacker04
{
strings:
		$a0 = { BC ?? ?? C3 2E FF 2E ?? ?? CF }

condition:
		$a0 at entrypoint
}
	
	
rule Unknownpacker03
{
strings:
		$a0 = { 06 1E 57 56 50 53 51 52 BD ?? ?? 0E 1F 8C }

condition:
		$a0 at entrypoint
}
	
	
rule Unknownpacker02
{
strings:
		$a0 = { FA 8C DE 8C CF 8E DF 8E C7 83 C7 ?? BB }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV112V114LZMA430ap0xSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? 60 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02CodeLock
{
strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov252b2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24 }

condition:
		$a0 at entrypoint
}
	
	
rule VxNecropolis
{
strings:
		$a0 = { 50 FC AD 33 C2 AB 8B D0 E2 F8 }

condition:
		$a0 at entrypoint
}
	
	
rule WinUpackv039finalrelocatedimagebaseByDwingc2005h2
{
strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 FF 66 1C B1 30 8B 5D 0C 03 D1 FF 16 73 4C 03 D1 FF 16 72 19 03 D1 FF 16 72 29 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C 8A 00 FF 66 18 83 C2 60 FF 16 87 5D 10 73 0C 03 D1 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8B D5 03 56 38 FF 56 0C }

condition:
		$a0 at entrypoint
}
	
	
rule MEW11SEv12
{
strings:
		$a0 = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule aPackv062
{
strings:
		$a0 = { 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6 }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPackerV100BeRoSignbyfly
{
strings:
		$a0 = { BA ?? ?? ?? ?? 8D B2 ?? ?? ?? ?? 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15 ?? ?? ?? ?? 5F 5A 85 C0 74 2F 8B C8 8B 03 85 C0 74 22 0F BA F0 1F 72 04 8D 44 ?? ?? 51 52 57 50 51 FF 15 ?? ?? ?? ?? 5F 5A 59 85 C0 74 0B AB 83 C3 04 EB D8 83 C6 14 EB AA 61 C3 }

condition:
		$a0
}
	
	
rule MEW11SEv11
{
strings:
		$a0 = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule tElockv071
{
strings:
		$a0 = { 60 E8 ED 10 00 00 C3 83 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv070
{
strings:
		$a0 = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }

condition:
		$a0 at entrypoint
}
	
	
rule AsCryptv01SToRMneedstobeadded
{
strings:
		$a0 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 83 ?? ?? E2 }
	$a1 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 E2 }
	$a2 = { 81 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? E2 ?? EB }

condition:
		$a0 or $a1 or $a2
}
	
	
rule PAVCryptorPawningAntiVirusCryptormasha_dev
{
strings:
		$a0 = { 53 56 57 55 BB 2C ?? ?? 70 BE 00 30 00 70 BF 20 ?? ?? 70 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 00 70 00 74 06 FF 15 54 30 00 70 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 1C 30 00 70 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 14 30 00 70 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 8F FA FF FF FF 15 20 30 00 70 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 ?? ?? 70 00 74 06 FF 15 10 ?? ?? 70 8B 06 50 E8 A9 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 00 70 E8 26 FF FF FF C3 90 8F 05 04 30 00 70 E9 E9 FF FF FF C3 }

condition:
		$a0
}
	
	
rule FucknJoy10cUsAr
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 }

condition:
		$a0
}
	
	
rule ExeShieldCryptor13RCTomCommander
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

condition:
		$a0 at entrypoint
}
	
	
rule CrinklerV01V02RuneLHStubbeandAskeSimonChristensen
{
strings:
		$a0 = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule VxGRUNT4Family
{
strings:
		$a0 = { E8 1C 00 8D 9E 41 01 40 3E 8B 96 14 03 B9 EA 00 87 DB F7 D0 31 17 83 C3 02 E2 F7 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule nPackV112002006BetaNEOxuinC
{
strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 EC 01 00 00 E8 F8 06 00 00 E8 03 06 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule VxEddie1800
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E }

condition:
		$a0 at entrypoint
}
	
	
rule ExeShieldv37ExeShieldTeamh
{
strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F 8C B9 0A FC EC E4 82 97 AE 0F 18 D2 47 1B 65 EA 46 A5 FD 3E 9D 75 2A 62 80 60 F9 B0 0D E1 AC 12 0E 9D 24 D5 43 CE 9A D6 18 BF 22 DA 1F 72 76 B0 98 5B C2 64 BC AE D8 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV2312Jitit
{
strings:
		$a0 = { 6A 00 FF 15 ?? ?? ?? ?? E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }

condition:
		$a0 at entrypoint
}
	
	
rule PrincessSandyv10eMiNENCEProcessPatcherPatch
{
strings:
		$a0 = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 57 6A 00 E8 CE 00 00 00 85 C0 74 78 BD 50 C3 00 00 8B 3D 04 20 40 00 8B 07 8D 3C 07 83 C7 04 89 3D 04 20 40 00 8B 0F 83 C7 04 8B 1F 83 C7 04 4D 85 ED 74 57 60 6A 00 51 68 5C 20 40 00 53 FF 35 4C 20 40 00 E8 93 00 00 00 85 C0 61 74 E1 8B C1 60 BE 5C 20 40 00 F3 A6 74 03 61 EB D2 60 6A 00 50 57 53 FF 35 4C 20 40 00 E8 7A 00 00 00 85 C0 74 20 61 83 3C 07 00 74 2D 03 F8 EB A8 B8 5E 21 40 00 EB 13 B8 7C 21 40 00 EB 0C B8 9E 21 40 00 EB 05 B8 CF 21 40 00 6A 00 68 56 }

condition:
		$a0
}
	
	
rule vprotector12vcasmh
{
strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 E8 05 00 00 00 0F 01 EB 05 E8 EB FB 00 00 83 C4 04 E8 08 00 00 00 0F 01 83 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule aPackv082
{
strings:
		$a0 = { 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB }

condition:
		$a0 at entrypoint
}
	
	
rule PEPaCKv10CCopyright1998byANAKiNh
{
strings:
		$a0 = { C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 2D 3D FE 20 50 45 2D 50 41 43 4B 20 76 31 2E 30 20 2D FE 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 31 39 39 38 20 62 79 20 41 4E 41 4B 69 4E 20 FE 3D 2D 20 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

condition:
		$a0
}
	
	
rule CAVisualObjects2025
{
strings:
		$a0 = { 89 25 ?? ?? ?? ?? 33 ED 55 8B EC E8 ?? ?? ?? ?? 8B D0 81 E2 FF 00 00 00 89 15 ?? ?? ?? ?? 8B D0 C1 EA 08 81 E2 FF 00 00 00 A3 ?? ?? ?? ?? D1 E0 0F 93 C3 33 C0 8A C3 A3 ?? ?? ?? ?? 68 FF 00 00 00 E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? BB }
	$a1 = { 89 25 ?? ?? ?? ?? 33 ED 55 8B EC E8 ?? ?? ?? ?? 8B D0 81 E2 FF 00 00 00 89 15 ?? ?? ?? ?? 8B D0 C1 EA 08 81 E2 FF 00 00 00 A3 ?? ?? ?? ?? D1 E0 0F 93 C3 33 C0 8A C3 A3 ?? ?? ?? ?? 68 FF 00 00 00 E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? BB ?? ?? ?? ?? C7 03 44 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule NJoiner01AsmVersionNEX
{
strings:
		$a0 = { 6A 00 68 00 14 40 00 68 00 10 40 00 6A 00 E8 14 00 00 00 6A 00 E8 13 00 00 00 CC FF 25 AC 12 40 00 FF 25 B0 12 40 00 FF 25 B4 12 40 00 FF 25 B8 12 40 00 FF 25 BC 12 40 00 FF 25 C0 12 40 00 FF 25 C4 12 40 00 FF 25 C8 12 40 00 FF 25 CC 12 40 00 FF 25 D0 12 40 00 FF 25 D4 12 40 00 FF 25 D8 12 40 00 FF 25 DC 12 40 00 FF 25 E4 12 40 00 FF 25 EC 12 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsiduim1304ObsiduimSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 }

condition:
		$a0 at entrypoint
}
	
	
	
	
rule PseudoSigner01CodeSafe20Anorganix
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PEProtect09
{
strings:
		$a0 = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F }

condition:
		$a0
}
	
	
rule PatchCreationWizard12BytePatch
{
strings:
		$a0 = { E8 7F 03 00 00 6A 00 E8 24 03 00 00 A3 B8 33 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 2C 03 00 00 6A 00 E8 EF 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 B8 33 40 00 E8 1B 03 00 00 50 6A 01 68 80 00 00 00 FF 75 }

condition:
		$a0
}
	
	
rule ocBat2Exe10OC
{
strings:
		$a0 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 58 3C 40 00 E8 6C FA FF FF 33 C0 55 68 8A 3F 40 00 64 FF 30 64 89 20 6A 00 6A 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 81 E9 FF FF 8B 45 EC E8 41 F6 FF FF 50 E8 F3 FA FF FF 8B F8 83 FF FF 0F 84 83 02 00 00 6A 02 6A 00 6A EE 57 E8 FC FA FF FF 6A 00 68 60 99 4F 00 6A 12 68 18 57 40 00 57 E8 E0 FA FF FF 83 3D 60 99 4F 00 12 0F 85 56 02 00 00 8D 45 E4 50 8D 45 E0 BA 18 57 40 00 B9 40 42 0F 00 E8 61 F4 FF FF 8B 45 E0 B9 12 00 00 00 BA 01 00 00 00 E8 3B F6 FF FF 8B 45 E4 8D 55 E8 E8 04 FB ?? ?? ?? ?? E8 B8 58 99 4F 00 E8 67 F3 FF FF 33 C0 A3 60 99 4F 00 8D 45 DC 50 B9 05 00 00 00 BA 01 00 00 00 A1 58 99 4F 00 E8 04 F6 FF FF 8B 45 DC BA A4 3F 40 00 E8 E3 F4 FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV119DllaPlib043ap0xnbspnbspSignbyfly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 89 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }

condition:
		$a0 at entrypoint
}
	

	
	
rule ASDPack20asd
{
strings:
		$a0 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8D 49 00 1F 01 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 90 }
	$a1 = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }
	$a2 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }

condition:
		$a0 or $a1 or $a2 at entrypoint
}
	
	
rule WATCOMCCDLL
{
strings:
		$a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 }

condition:
		$a0 at entrypoint
}
	
	
rule ShrinkWrapv14
{
strings:
		$a0 = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule CorelDrawCMXGraphicsformat
{
strings:
		$a0 = { 52 49 46 46 ?? ?? ?? ?? 43 4D 58 31 }

condition:
		$a0
}
	
	
rule MSRunTimeLibrary1990199209
{
strings:
		$a0 = { B4 30 CD 21 3C 02 73 ?? C3 8C DF 8B 36 ?? ?? 2E }

condition:
		$a0 at entrypoint
}
	
	
rule VxSK
{
strings:
		$a0 = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01VOBProtectCD5Anorganix
{
strings:
		$a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXFreak01BorlandDelphiHMX0101
{
strings:
		$a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }

condition:
		$a0
}
	
	
rule EXEjoinerAmok
{
strings:
		$a0 = { A1 14 A1 40 00 C1 E0 02 A3 18 A1 40 }

condition:
		$a0 at entrypoint
}
	
	
rule EmbedPEv124cyclotron
{
strings:
		$a0 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo37xSiliconRealmsToolworks
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 ?? 87 DB 7A F0 ?? ?? 61 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 ?? 8B 04 24 EB 03 7A 29 ?? C6 00 90 C3 ?? 70 F0 87 D2 71 07 ?? ?? 40 8B DB 7A 11 EB 08 ?? EB F7 EB C3 ?? 7A E9 70 DA 7B D1 71 F3 ?? 7B F3 71 D6 ?? 9D 61 83 ED 06 B8 3B 01 00 00 03 C5 33 DB 81 C3 01 01 01 01 31 18 81 38 78 54 00 00 74 04 31 18 EB EC }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv04xv05x
{
strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov301v305
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 75 02 EB 15 EB 33 C9 75 18 7A 0C 70 0E EB 0D E8 72 0E 79 F1 FF 15 00 79 09 74 F0 EB 87 DB 7A F0 A0 33 61 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 A0 8B 04 24 EB 03 7A 29 E9 C6 00 90 C3 E8 70 F0 87 D2 71 07 E9 00 40 8B DB 7A 11 EB 08 E9 EB F7 EB C3 E8 7A E9 70 DA 7B D1 71 F3 E9 7B }

condition:
		$a0 at entrypoint
}
	
	
rule CodeVirtualizerV1310OreansTechnologiesSignbyfly
{
strings:
		$a0 = { 60 9C FC E8 00 00 00 00 5F 81 EF ?? ?? ?? ?? 8B C7 81 C7 ?? ?? ?? ?? 3B 47 2C 75 02 EB 2E 89 47 2C B9 A7 00 00 00 EB 05 01 44 8F ?? 49 0B C9 75 F7 83 7F 40 00 74 15 8B 77 40 03 F0 EB 09 8B 1E 03 D8 01 03 83 C6 04 83 3E 00 75 F2 8B 74 24 24 8B DE 03 F0 B9 01 00 00 00 33 C0 F0 0F B1 4F 30 75 F7 AC }

condition:
		$a0
}
	
	
rule DingBoysPElockv007
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule mPack003DeltaAziz
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 33 C0 89 45 F0 B8 A8 76 00 10 E8 67 C4 FF FF 33 C0 55 68 C2 78 00 10 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 08 A5 00 10 33 C0 55 68 A5 78 00 10 64 FF 30 64 89 20 A1 08 A5 00 10 E8 FA C9 FF FF 83 F8 FF }
	$a1 = { 55 8B EC 83 C4 F0 33 C0 89 45 F0 B8 A8 76 00 10 E8 67 C4 FF FF 33 C0 55 68 C2 78 00 10 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 08 A5 00 10 33 C0 55 68 A5 78 00 10 64 FF 30 64 89 20 A1 08 A5 00 10 E8 FA C9 FF FF 83 F8 FF 75 0A E8 88 B2 FF FF E9 1B 01 00 00 C7 05 14 A5 00 10 32 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 C9 C9 FF FF BA 14 A5 00 10 A1 08 A5 00 10 B9 04 00 00 00 E8 C5 C9 FF FF 83 3D 14 A5 00 10 32 77 0A E8 47 B2 FF FF E9 DA 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 92 C9 FF FF BA 18 A5 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ThinstallEmbeddedV2545JititSignbyfly
{
strings:
		$a0 = { E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SixtoFourv10
{
strings:
		$a0 = { 50 55 4C 50 83 ?? ?? FC BF ?? ?? BE ?? ?? B5 ?? 57 F3 A5 C3 33 ED }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoinerSmallbuild029GlOFF
{
strings:
		$a0 = { 50 32 C4 8A C3 58 E8 DE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ThemidaWinLicenseV1XNoCompressionSecureEngineOreansTechnologies
{
strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule WinUpackv030betaByDwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 }

condition:
		$a0
}
	
	
rule Armadillov260b2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov260b1
{
strings:
		$a0 = { 55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphiv60v70
{
strings:
		$a0 = { 53 8B D8 33 C0 A3 00 ?? ?? ?? 06 A0 0E 80 ?? ?? 0F FA 30 ?? ?? ?? 0A 10 ?? ?? ?? 0A 30 ?? ?? ?? 03 3C 0A 30 ?? ?? ?? 03 3C 0A 30 ?? ?? ?? E8 }
	$a1 = { 53 8B D8 33 C0 A3 0? ?? ?? ?0 6A 00 E8 0? ?? ?0 FF A3 0? ?? ?? ?0 A1 0? ?? ?? ?0 A3 0? ?? ?? ?0 33 C0 A3 0? ?? ?? ?0 33 C0 A3 0? ?? ?? ?0 E8 }
	$a2 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 }
	$a3 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FB FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF 8B 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 8B 15 ?? ?? ?? ?? E8 ?? ?? FF FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF E8 ?? ?? FB FF 8D 40 }
	$a4 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }

condition:
		$a0 at entrypoint or $a1 or $a2 or $a3 at entrypoint or $a4 at entrypoint
}
	
	
rule ExeLockerv10IonIce
{
strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PellesC300400450EXEX86CRTDLL
{
strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 C7 45 FC ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 BE ?? ?? ?? ?? EB }

condition:
		$a0
}
	
	
rule Armadillov190a
{
strings:
		$a0 = { 55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv305c4Modified
{
strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule APatchGUIv11
{
strings:
		$a0 = { 52 31 C0 E8 FF FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01CDCopsIIAnorganix
{
strings:
		$a0 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule SetupFactory6xCustom
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? 61 40 00 68 ?? 43 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? 61 40 00 33 D2 8A D4 89 15 A0 A9 40 00 8B C8 81 E1 FF 00 00 00 89 0D }

condition:
		$a0 at entrypoint
}
	
	
rule AlexProtector10Alex
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1322ObsidiumSoftware
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04 }

condition:
		$a0 at entrypoint
}
	
	
rule PrivateEXEProtector20SetiSoft
{
strings:
		$a0 = { 89 ?? ?? 38 00 00 00 8B ?? 00 00 00 00 81 ?? ?? ?? ?? ?? 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo301305
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F }

condition:
		$a0
}
	
	
rule MSLRH032afakeEXE32Pack13xemadicius
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 90 83 C4 14 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 }

condition:
		$a0
}
	
	
rule RCryptor16dbyVaskaUsArsign210320072222
{
strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 40 A1 14 13 B8 00 10 14 13 90 3D 24 C0 14 13 74 06 80 30 F6 40 EB F3 B8 8C 20 18 13 90 3D B9 27 18 13 74 06 80 30 89 40 EB F3 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule IProtect10FxlibdllmodebyFuXdas
{
strings:
		$a0 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 4C 69 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED 71 10 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 63 10 40 00 }
	$a1 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 4C 69 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED 71 10 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 63 10 40 00 8D 85 3C 10 40 00 50 FF B5 63 10 40 00 E8 92 00 00 00 0B C0 74 13 89 85 5F 10 40 00 8D 85 49 10 40 00 50 FF 95 5F 10 40 00 8B 85 67 10 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 FA FD FF FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule SecureEXE30ZipWorx
{
strings:
		$a0 = { E9 B8 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PCGuard500d
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }

condition:
		$a0
}
	
	
rule MSLRHv032afakePEtite21emadiciush
{
strings:
		$a0 = { B8 00 50 40 00 6A 00 68 BB 21 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorv12CGSoftLabs
{
strings:
		$a0 = { 45 78 50 72 2D 76 2E 31 2E 32 2E }

condition:
		$a0
}
	
	
rule FSG120EngdulekxtMicrosoftVisualC60
{
strings:
		$a0 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }

condition:
		$a0
}
	
	
rule MicrosoftVisualC70
{
strings:
		$a0 = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 8B 75 0C }
	$a1 = { 6A 18 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 94 00 00 00 8B C7 E8 ?? ?? ?? ?? 89 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MicrosoftVisualC71
{
strings:
		$a0 = { 55 8B EC 83 EC 08 53 56 57 55 FC 8B 5D 0C 8B 45 08 F7 40 04 06 00 00 00 0F 85 AB 00 00 00 89 45 F8 8B 45 10 89 45 FC 8D 45 F8 89 43 FC 8B 73 0C 8B 7B 08 53 E8 ?? ?? ?? ?? 83 C4 04 0B C0 74 7B 83 FE FF 74 7D 8D 0C 76 8B 44 8F 04 0B C0 74 59 56 55 }
	$a1 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 39 75 0C 0F 84 ?? ?? ?? ?? 33 C0 40 5E 5D C2 0C 00 }
	$a2 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 }
	$a3 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? 59 59 33 C0 40 5E 5D C2 0C 00 }
	$a4 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 75 44 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 }
	$a5 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 75 0E 39 35 ?? ?? ?? ?? 7E 2D FF 0D ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 75 3D 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 75 04 33 C0 EB 67 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 }

condition:
		$a0 or $a1 or $a2 or $a3 or $a4 or $a5
}
	
	
rule NullsoftPIMPInstallSystemv13x
{
strings:
		$a0 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }

condition:
		$a0 at entrypoint
}
	
	
rule Themida10xx18xxnocompressionOreansTechnologiesh
{
strings:
		$a0 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }
	$a1 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA ?? ?? ?? ?? 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule UPXInlinerv10byGPcH
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 05 FF FF FF 85 C0 0F 84 06 03 00 00 89 85 C5 FE FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD A9 FE FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 09 FF FF FF FF B5 05 FF FF FF 56 57 FF 95 C5 FE FF FF 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB CE 68 00 80 00 00 6A 00 FF B5 C5 FE FF FF FF 95 09 FF FF FF 8D }

condition:
		$a0
}
	
	
rule PECompactv140b5v140b6
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02PEIntro10
{
strings:
		$a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A }

condition:
		$a0 at entrypoint
}
	
	
rule FreePascal200Win32
{
strings:
		$a0 = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }
	$a1 = { C6 05 ?? ?? ?? ?? 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ThinstallEmbeddedV2620V2623JititSignbyfly
{
strings:
		$a0 = { E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxExplosion1000
{
strings:
		$a0 = { E8 ?? ?? 5E 1E 06 50 81 ?? ?? ?? 56 FC B8 21 35 CD 21 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 26 ?? ?? ?? ?? ?? ?? 74 ?? 8C D8 48 8E D8 }

condition:
		$a0 at entrypoint
}
	
	
rule PKZIPSFXv11198990
{
strings:
		$a0 = { FC 2E 8C 0E ?? ?? A1 ?? ?? 8C CB 81 C3 ?? ?? 3B C3 72 ?? 2D ?? ?? 2D ?? ?? FA BC ?? ?? 8E D0 FB }

condition:
		$a0 at entrypoint
}
	
	
rule PureBasicDLLNeilHodgson
{
strings:
		$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule PUNiSHERV15DemoFEUERRADER
{
strings:
		$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOPv110v111
{
strings:
		$a0 = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 2F CD 21 B0 ?? B4 4C CD 21 50 B8 ?? ?? 58 EB }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1336ObsidiumSoftware
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 }
	$a1 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule DualseXeEncryptor10bDual
{
strings:
		$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 3A 04 00 00 89 28 33 FF 8D 85 80 03 00 00 8D 8D 3A 04 00 00 2B C8 8B 9D 8A 04 00 00 E8 24 02 00 00 8D 9D 58 03 00 00 8D B5 7F 03 00 00 46 80 3E 00 74 24 56 FF 95 58 05 00 00 46 80 3E 00 75 FA 46 80 3E 00 74 E7 50 56 50 FF 95 5C 05 00 00 89 03 58 83 C3 04 EB E3 8D 85 69 02 00 00 FF D0 8D 85 56 04 00 00 50 68 1F 00 02 00 6A 00 8D 85 7A 04 00 00 50 }

condition:
		$a0 at entrypoint
}
	
	
rule FreePascalv1010win32GUI
{
strings:
		$a0 = { C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 }

condition:
		$a0
}
	
	
rule MarjinZEXEScramblerSEbyMarjinZ
{
strings:
		$a0 = { E8 A3 02 00 00 E9 35 FD FF FF FF 25 C8 20 00 10 6A 14 68 C0 21 00 10 E8 E4 01 00 00 FF 35 7C 33 00 10 8B 35 8C 20 00 10 FF D6 59 89 45 E4 83 F8 FF 75 0C FF 75 08 FF 15 88 20 00 10 59 EB 61 6A 08 E8 02 03 00 00 59 83 65 FC 00 FF 35 7C 33 00 10 FF D6 89 45 E4 FF 35 78 33 00 10 FF D6 89 45 E0 8D 45 E0 50 8D 45 E4 50 FF 75 08 E8 D1 02 00 00 89 45 DC FF 75 E4 8B 35 74 20 00 10 FF D6 A3 7C 33 00 10 FF 75 E0 FF D6 83 C4 1C A3 78 33 00 10 C7 45 FC FE FF FF FF E8 09 00 00 00 8B 45 DC E8 A0 01 00 00 C3 }

condition:
		$a0
}
	
	
rule nPack111502006BetaNEOx
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 }
	$a1 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule DingBoysPElockPhantasmv15b3
{
strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }

condition:
		$a0 at entrypoint
}
	
	
rule CRYPTVersion17cDismemberEXE
{
strings:
		$a0 = { 0E 17 9C 58 F6 ?? ?? 74 ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule ShellModify01pll621
{
strings:
		$a0 = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01MacromediaFlashProjector60Anorganix
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C E9 }

condition:
		$a0 at entrypoint
}
	
	
rule MinGWv32x_mainCRTStartup
{
strings:
		$a0 = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 40 00 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule bambamV001bedrockSignbyfly
{
strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF ?? ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv0761dosexe
{
strings:
		$a0 = { B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8C C8 05 ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC }

condition:
		$a0 at entrypoint
}
	
	
rule aPackv098bDSESnotsaved
{
strings:
		$a0 = { 8C CB BA ?? ?? 03 DA FC 33 F6 33 FF 4B 8E DB 8D ?? ?? ?? 8E C0 B9 ?? ?? F3 A5 4A 75 }

condition:
		$a0
}
	
	
rule ASProtectvIfyouknowthisversionpostonPEiDboardh2
{
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule VxKuku886
{
strings:
		$a0 = { 06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 ?? ?? ?? ?? ?? 90 B4 2F CD 21 53 }

condition:
		$a0 at entrypoint
}
	
	
rule Aluwainv809
{
strings:
		$a0 = { 8B EC 1E E8 ?? ?? 9D 5E }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote12DLLDemoSISTeam
{
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B }
	$a1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule LSIC86RunTimeLibray
{
strings:
		$a0 = { B8 ?? ?? 8E C0 06 17 BC ?? ?? 26 8C ?? ?? ?? B4 30 CD 21 26 A3 ?? ?? FC }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02ExeSmasher
{
strings:
		$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B }

condition:
		$a0 at entrypoint
}
	
	
rule ImgSoftwareSetgraphicsfile
{
strings:
		$a0 = { 53 43 4D 49 20 20 20 31 41 54 }

condition:
		$a0
}
	
	
rule PECompactv126b1v126b2
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? 05 0E }

condition:
		$a0 at entrypoint
}
	
	
rule Cruncherv10
{
strings:
		$a0 = { 2E ?? ?? ?? ?? 2E ?? ?? ?? B4 30 CD 21 3C 03 73 ?? BB ?? ?? 8E DB 8D ?? ?? ?? B4 09 CD 21 06 33 C0 50 CB }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote1214SEDLLSISTeam
{
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC 11 DB }

condition:
		$a0 at entrypoint
}
	
	
rule TurboC1990orTurboC1988
{
strings:
		$a0 = { BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 8B ?? ?? ?? 8B ?? ?? ?? 8E DA }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacKV37LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakeSVKP111emadicius
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 }

condition:
		$a0
}
	
	
rule tElock099tE
{
strings:
		$a0 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 }

condition:
		$a0 at entrypoint
}
	
	
rule Alloyv1x2000
{
strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner153Stubengine171GlOFF
{
strings:
		$a0 = { 86 D6 90 86 F2 B9 93 60 08 FE 90 86 D6 90 86 F2 B9 9D 13 45 01 86 D6 90 86 F2 81 C2 93 60 08 FE 33 C9 B9 30 74 4D FF 86 D6 90 86 F2 33 C9 C7 05 B4 17 40 00 00 00 00 00 90 68 00 01 00 00 68 D1 17 40 00 6A 00 E8 CE 02 00 00 90 33 C9 86 D6 90 86 F2 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 D1 17 40 00 E8 9E 02 00 00 A3 CD 17 40 00 86 D6 }
	$a1 = { E8 02 FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A8 10 40 00 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule PseudoSigner02MicrosoftVisualC70DLLAnorganix
{
strings:
		$a0 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 }

condition:
		$a0 at entrypoint
}
	
	
rule PeCompactv208BitsumTechnologiessignaturebyloveboom
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv70
{
strings:
		$a0 = { 6A 0C 68 88 BF 01 10 E8 B8 1C 00 00 33 C0 40 89 45 E4 8B 75 0C 33 FF 3B F7 75 0C 39 3D 6C 1E 12 10 0F 84 B3 00 00 00 89 7D FC 3B F0 74 05 83 FE 02 75 31 A1 98 36 12 10 3B C7 74 0C FF 75 10 56 }
	$a1 = { 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? ?? 8B 46 ?? A3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PECompactv20
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptorV21Xsoftcompletecom
{
strings:
		$a0 = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }

condition:
		$a0
}
	
	
rule PCShrinkerv045
{
strings:
		$a0 = { BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor226minimumprotectionwwwstrongbitcom
{
strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 E8 ?? ?? ?? 00 89 45 F8 E9 ?? ?? ?? ?? 0F 83 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 14 24 5A 57 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 58 81 C0 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 81 C8 ?? ?? ?? ?? 81 E0 }

condition:
		$a0
}
	
	
rule MicrosoftVisualC42
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 }

condition:
		$a0 at entrypoint
}
	
	
rule Crunch5BitArts
{
strings:
		$a0 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00 }

condition:
		$a0
}
	
	
rule SoftSentryv211
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectv123RC4build0807dllAlexeySolodovnikovh
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov300
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeGuarderv18Exeiconcomh
{
strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 75 1C 8B D0 03 D2 03 55 F0 0F B7 12 C1 E2 02 03 55 EC 8B 12 03 16 8B 4D F4 89 51 08 EB 04 40 49 75 A9 8B 5D F4 8D 83 A1 00 00 00 50 8B 06 50 FF 53 08 89 43 0C 8D 83 AE 00 00 00 50 8B 06 50 FF 53 08 89 43 10 8D 83 BA 00 00 00 50 8B 06 50 FF 53 08 89 43 14 8D 83 C6 00 00 00 50 8B 06 50 FF 53 08 89 43 18 8D 83 D7 00 00 00 50 8B 06 50 FF 53 08 89 43 1C 8D 83 E0 00 00 00 50 8B 06 50 FF 53 08 }

condition:
		$a0 at entrypoint
}
	
	
rule Fusion10jaNooNi
{
strings:
		$a0 = { 68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MingWin32vh
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FE FF FF 90 8D B4 26 00 00 00 00 55 }

condition:
		$a0 at entrypoint
}
	
	
rule UpxLock1012CyberDoomTeamXBoBBobSoft
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }

condition:
		$a0 at entrypoint
}
	
	
rule PCPEEncryptorAlphapreview
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 00 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphiv30
{
strings:
		$a0 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule VxKeypress1212
{
strings:
		$a0 = { E8 ?? ?? E8 ?? ?? E8 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EA ?? ?? ?? ?? 1E 33 DB 8E DB BB }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor239DLLminimumprotectionwwwstrongbitcom
{
strings:
		$a0 = { 51 68 ?? ?? ?? ?? 87 2C 24 8B CD 5D 81 E1 ?? ?? ?? ?? E9 ?? ?? ?? 00 89 45 F8 51 68 ?? ?? ?? ?? 59 81 F1 ?? ?? ?? ?? 0B 0D ?? ?? ?? ?? 81 E9 ?? ?? ?? ?? E9 ?? ?? ?? 00 81 C2 ?? ?? ?? ?? E8 ?? ?? ?? 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C }

condition:
		$a0
}
	
	
rule NsPackV14LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UnknownProtectedModecompiler2
{
strings:
		$a0 = { FA FC 0E 1F E8 ?? ?? 8C C0 66 0F B7 C0 66 C1 E0 ?? 66 67 A3 }

condition:
		$a0 at entrypoint
}
	
	
rule UnknownProtectedModecompiler1
{
strings:
		$a0 = { FA BC ?? ?? 8C C8 8E D8 E8 ?? ?? E8 ?? ?? E8 ?? ?? 66 B8 ?? ?? ?? ?? 66 C1 }

condition:
		$a0 at entrypoint
}
	
	
rule tElock099
{
strings:
		$a0 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 02 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? 02 00 00 }

condition:
		$a0
}
	
	
rule EXECryptorV21XSoftCompletecom
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02LCCWin32DLLAnorganix
{
strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }

condition:
		$a0 at entrypoint
}
	
	
rule VProtectorV11Avcasm
{
strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1300ObsidiumSoftware
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 47 26 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphi5PortionsCopyrightc198399Borlandh
{
strings:
		$a0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 39 20 42 6F 72 6C 61 6E 64 00 }

condition:
		$a0
}
	
	
rule TASMMASM
{
strings:
		$a0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeLocker10IonIce
{
strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EXE2COMPacked
{
strings:
		$a0 = { BD ?? ?? 89 ?? ?? ?? 81 ?? ?? ?? ?? ?? 8C ?? ?? ?? 8C C8 05 ?? ?? 8E C0 BE ?? ?? 8B FE 0E 57 54 59 F3 A4 06 68 ?? ?? CB }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftFORTRAN
{
strings:
		$a0 = { FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC 8C DB 8E C3 BB ?? ?? B9 ?? ?? 9A ?? ?? ?? ?? 80 ?? ?? ?? ?? 74 ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule USERNAMEv300
{
strings:
		$a0 = { FB 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 8C C8 2B C1 8B C8 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 33 C0 8E D8 06 0E 07 FC 33 F6 }

condition:
		$a0 at entrypoint
}
	
	
rule nSpackV2xLiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }

condition:
		$a0
}
	
	
rule SoftProtectSoftProtectbyru
{
strings:
		$a0 = { E8 0C 15 00 00 8D 85 2F 14 00 00 C7 00 00 00 00 00 E8 29 0F 00 00 E8 F6 14 00 00 8D 85 20 01 00 00 50 E8 AA 16 00 00 83 }
	$a1 = { EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 59 83 01 01 80 39 5C }
	$a2 = { EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 59 83 01 01 80 39 5C 75 F2 33 C4 74 0C 23 C4 0B C4 C6 01 59 C6 01 59 EB E2 90 E8 44 14 ?? ?? 8D 85 CF 13 ?? ?? C7 ?? ?? ?? ?? ?? E8 61 0E ?? ?? E8 2E 14 ?? ?? 8D 85 E4 01 ?? ?? 50 E8 E2 15 ?? ?? 83 BD 23 01 ?? ?? 01 75 07 E8 21 0D ?? ?? EB 09 8D 85 CF 13 ?? ?? 83 08 01 83 BD 1F 01 ?? ?? 01 75 07 E8 3E 0C ?? ?? EB 05 E8 A8 0C ?? ?? E8 B3 02 ?? ?? 8D 85 63 02 ?? ?? 50 E8 A3 15 ?? ?? 8D 85 F5 02 ?? ?? 50 E8 97 15 ?? ?? E8 E2 01 ?? ?? 8D 85 09 05 ?? ?? 50 E8 86 15 ?? ?? 8D 85 F8 0F ?? ?? 50 E8 7A 15 ?? ?? 8D 85 88 0F ?? ?? 50 E8 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule MicrosoftVisualBasicv60
{
strings:
		$a0 = { FF 25 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF ?? ?? ?? ?? ?? ?? 30 }

condition:
		$a0
}
	
	
rule WWPACKv305c4Unextractable
{
strings:
		$a0 = { 03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule Escargot01finalMeat
{
strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 92 ?? ?? ?? 8B 00 FF D0 50 B8 CD ?? ?? ?? 81 38 DE C0 37 13 75 2D 68 C9 ?? ?? ?? 6A 40 68 00 ?? 00 00 68 00 00 ?? ?? B8 96 ?? ?? ?? 8B 00 FF D0 8B 44 24 F0 8B 4C 24 F4 EB 05 49 C6 04 01 40 0B C9 75 F7 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 }

condition:
		$a0 at entrypoint
}
	
	
rule MetrowerksCodeWarriorv20GUI
{
strings:
		$a0 = { 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 ?? ?? 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

condition:
		$a0
}
	
	
rule IBMPictureMakergraphicsfile
{
strings:
		$a0 = { 00 ?? C1 ?? 00 ?? ?? ?? ?? 02 00 01 }

condition:
		$a0
}
	
	
rule TurboCorBorlandC
{
strings:
		$a0 = { BA ?? ?? 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA }

condition:
		$a0 at entrypoint
}
	
	
rule UnnamedScrambler21Beta211p0ke
{
strings:
		$a0 = { 55 8B EC B9 15 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? 3A ?? ?? E8 ?? EE FF FF 33 C0 55 68 ?? 43 ?? ?? 64 FF 30 64 89 20 BA ?? 43 ?? ?? B8 E4 64 ?? ?? E8 0F FD FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? EE FF FF BA E8 64 ?? ?? 8B C3 8B 0D E4 64 ?? ?? E8 }
	$a1 = { 55 8B EC B9 15 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? 3A ?? ?? E8 ?? EE FF FF 33 C0 55 68 ?? 43 ?? ?? 64 FF 30 64 89 20 BA ?? 43 ?? ?? B8 E4 64 ?? ?? E8 0F FD FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? EE FF FF BA E8 64 ?? ?? 8B C3 8B 0D E4 64 ?? ?? E8 ?? D7 FF FF B8 F8 ?? ?? ?? BA 04 00 00 00 E8 ?? EF FF FF 33 C0 A3 F8 ?? ?? ?? BB ?? ?? ?? ?? C7 45 EC E8 64 ?? ?? C7 45 E8 ?? ?? ?? ?? C7 45 E4 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? B8 E0 ?? ?? ?? BA 04 00 00 00 E8 ?? EF FF FF 68 F4 01 00 00 E8 ?? EE FF FF 83 7B 04 00 75 0B 83 3B 00 0F 86 ?? 07 00 00 EB 06 0F 8E ?? 07 00 00 8B 03 8B D0 B8 E4 ?? ?? ?? E8 ?? E5 FF FF B8 E4 ?? ?? ?? E8 ?? E3 FF FF 8B D0 8B 45 EC 8B 0B E8 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule MSLRHv032afakenSPack13emadiciush
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule VProtectorV10Build20041213
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1A 89 40 00 68 56 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

condition:
		$a0 at entrypoint
}
	
	
rule NoodleCryptv20
{
strings:
		$a0 = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }
	$a1 = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule PoPa001PackeronPascalbagie
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 A4 3E 00 10 E8 30 F6 FF FF 33 C0 55 68 BE 40 00 10 ?? ?? ?? ?? 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 62 E7 FF FF 8B 45 EC E8 32 F2 FF FF 50 E8 B4 F6 FF FF A3 64 66 00 10 33 D2 55 68 93 40 00 10 64 FF 32 64 89 22 83 3D 64 66 00 10 FF 0F 84 3A 01 00 00 6A 00 6A 00 6A 00 A1 64 66 00 10 50 E8 9B F6 FF FF 83 E8 10 50 A1 64 66 00 10 50 E8 BC F6 FF FF 6A 00 68 80 66 00 10 6A 10 68 68 66 00 10 A1 64 66 00 10 50 E8 8B F6 FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule NTkrnlSecureSuiteV01DLLNTkrnlSoftwareSignbyfly
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 8B 44 24 04 05 ?? ?? ?? ?? 50 E8 01 00 00 00 C3 C3 }

condition:
		$a0
}
	
	
rule GamehouseMediaProtectorVersionUnknown
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv042
{
strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePackV11XV12XMethod2bagie
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01MicrosoftVisualBasic60DLL
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF }

condition:
		$a0 at entrypoint
}
	
	
rule EXEManagerVersion301994cSolarDesigner
{
strings:
		$a0 = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo420SiliconRealmsToolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 F0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 84 A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 80 A5 4C 00 C1 E1 08 03 CA 89 0D 7C A5 4C 00 C1 E8 10 A3 78 A5 }

condition:
		$a0
}
	
	
rule InterchangeFormatFileIFFtypeWVQA
{
strings:
		$a0 = { 46 4F 52 4D ?? ?? ?? ?? 57 56 51 41 56 51 48 44 }

condition:
		$a0
}
	
	
rule AnslymCrypter
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A 68 30 1C 05 10 A1 60 56 05 10 50 E8 68 47 FB FF 8B }
	$a1 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A 68 30 1C 05 10 A1 60 56 05 10 50 E8 68 47 FB FF 8B D8 85 DB 0F 84 B6 02 00 00 53 A1 60 56 05 10 50 E8 F2 48 FB FF 8B F0 85 F6 0F 84 A0 02 00 00 E8 F3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Upackv021BetaSignbyhot_UNP
{
strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33 }

condition:
		$a0 at entrypoint
}
	
	
rule dUPv2xPatcherwwwdiablo2oo2cjbnet
{
strings:
		$a0 = { 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F }

condition:
		$a0
}
	
	
rule CrypKeyV56XDLLKenonicControlsLtd
{
strings:
		$a0 = { 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8 }

condition:
		$a0 at entrypoint
}
	
	
rule PEiDBundlev102v104BoBBobSoft
{
strings:
		$a0 = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

condition:
		$a0 at entrypoint
}
	
	
rule VxHeloween1172
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? 56 50 06 0E 1F 8C C0 01 ?? ?? 01 ?? ?? 80 ?? ?? ?? ?? 8B ?? ?? A3 ?? ?? 8A ?? ?? A2 ?? ?? B8 ?? ?? CD 21 3D }

condition:
		$a0 at entrypoint
}
	
	
rule PackedwithPKLITEv150withCRCcheck1
{
strings:
		$a0 = { 1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule SoftDefender1xRandyLi
{
strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 }
	$a1 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Pe123v2006412
{
strings:
		$a0 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 E8 00 00 00 00 58 C1 E8 0C C1 E0 0C 66 81 38 4D 5A 74 0C 2D 00 10 00 00 66 81 38 4D 5A 75 F4 C3 E8 00 00 00 00 58 83 E8 05 C3 8B C0 55 8B EC 81 C4 4C FE FF FF 53 6A 40 8D 85 44 FF FF FF 50 E8 BC FF FF FF 50 E8 8A FF FF FF 68 F8 00 00 00 8D 85 4C FE FF FF 50 E8 A5 FF FF FF 03 45 80 50 E8 70 FF FF FF E8 97 FF FF FF 03 85 CC FE FF FF 83 C0 34 89 45 FC E8 86 FF FF FF 03 85 CC FE FF FF 83 C0 38 89 45 8C 60 8B 45 FC 8B 00 89 45 F8 89 45 9C 8B 45 8C 8B 00 89 45 88 89 45 98 E8 0D 00 00 00 6B 65 72 6E 65 6C 33 }

condition:
		$a0 at entrypoint
}
	
	
rule DropperCreatorV01Conflict
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 8D 05 ?? ?? ?? ?? 29 C5 8D 85 ?? ?? ?? ?? 31 C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 }

condition:
		$a0
}
	
	
rule XCRv011
{
strings:
		$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }

condition:
		$a0 at entrypoint
}
	
	
rule XCRv013
{
strings:
		$a0 = { 93 71 08 ?? ?? ?? ?? ?? ?? ?? ?? 8B D8 78 E2 ?? ?? ?? ?? 9C 33 C3 ?? ?? ?? ?? 60 79 CE ?? ?? ?? ?? E8 01 ?? ?? ?? ?? 83 C4 04 E8 AB FF FF FF ?? ?? ?? ?? 2B E8 ?? ?? ?? ?? 03 C5 FF 30 ?? ?? ?? ?? C6 ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule XCRv012
{
strings:
		$a0 = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor13CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E }

condition:
		$a0 at entrypoint
}
	
	
rule NETexecutable
{
strings:
		$a0 = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxNcuLi1688
{
strings:
		$a0 = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule InnoSetupModulev129
{
strings:
		$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }

condition:
		$a0 at entrypoint
}
	
	
rule ProActivateV10XTurboPowerSoftwareCompany
{
strings:
		$a0 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? ?? 90 90 90 90 90 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? 83 C0 05 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0D 00 00 00 E8 85 E2 FF FF 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 7A 81 3D }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakeNeolite20emadicius
{
strings:
		$a0 = { E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 }

condition:
		$a0
}
	
	
rule Armadillov3xx
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinv11bycyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }

condition:
		$a0
}
	
	
rule SoftwareCompressv12BGSoftwareProtectTechnologiesh
{
strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 1A 0F 41 00 89 44 24 1C 61 C2 04 00 E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 }

condition:
		$a0 at entrypoint
}
	
	
rule dUP2xPatcherwwwdiablo2oo2cjbnet
{
strings:
		$a0 = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }

condition:
		$a0
}
	
	
rule CRYPToCRACksPEProtectorv093LucasFleischerh
{
strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00 00 81 EB 00 01 00 00 75 BE 90 72 ?? ?? ?? ?? 00 00 00 00 00 00 00 7A ?? ?? ?? 72 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 C1 00 46 61 74 61 6C 45 78 69 74 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack10betaap0xh
{
strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 48 02 00 00 56 FF D3 83 C4 08 8B B5 48 02 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 83 C0 04 89 85 44 02 00 00 EB 7A 56 FF 95 F1 01 00 00 89 85 40 02 00 00 8B C6 EB 4F 8B 85 44 02 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 44 02 00 00 C7 00 20 20 20 00 EB 06 FF B5 44 02 00 00 FF B5 40 02 00 00 FF 95 F5 01 00 00 89 07 83 C7 04 8B 85 44 02 00 00 EB 01 40 80 38 00 75 FA 40 89 85 44 02 00 00 80 38 00 75 AC EB 01 46 80 3E 00 75 FA 46 40 8B 38 83 C0 04 89 85 44 02 00 00 80 3E 01 75 81 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 48 02 00 00 FF 95 FD 01 00 00 61 68 ?? ?? ?? ?? C3 60 8B 74 24 24 8B 7C }

condition:
		$a0 at entrypoint
}
	
	
rule SoftComp1xBGSoftPT
{
strings:
		$a0 = { E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00 }

condition:
		$a0
}
	
	
rule EXECryptor2223compressedcodewwwstrongbitcom
{
strings:
		$a0 = { E8 00 00 00 00 58 ?? ?? ?? ?? ?? 8B 1C 24 81 EB ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 ?? ?? ?? 8B 04 18 FF D0 59 BA ?? ?? ?? ?? 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 ?? ?? ?? ?? 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 }
	$a1 = { E8 00 00 00 00 58 ?? ?? ?? ?? ?? 8B 1C 24 81 EB ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 ?? ?? ?? 8B 04 18 FF D0 59 BA ?? ?? ?? ?? 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 ?? ?? ?? ?? 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 B8 C8 ?? ?? ?? 8B 04 18 FF D0 59 58 5B 83 EB 05 C6 03 B8 43 89 03 83 C3 04 C6 03 C3 09 C9 74 46 89 C3 E8 A0 00 00 00 FC AD 83 F8 FF 74 38 53 89 CB 01 C3 01 0B 83 C3 04 AC 3C FE 73 07 25 FF 00 00 00 EB ED 81 C3 FE 00 00 00 09 C0 7A 09 66 AD 25 FF FF 00 00 EB DA AD 4E 25 FF FF FF 00 3D FF FF FF 00 75 CC ?? ?? ?? ?? ?? C3 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule FSG100Engdulekxt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }

condition:
		$a0
}
	
	
rule MicrosoftVisualC70Custom
{
strings:
		$a0 = { 60 BE 00 B0 44 00 8D BE 00 60 FB FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePEtite21emadicius
{
strings:
		$a0 = { B8 00 50 40 00 6A 00 68 BB 21 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB }

condition:
		$a0
}
	
	
rule PolyCryptPE214b215JLabSoftwareCreationshoep
{
strings:
		$a0 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }

condition:
		$a0
}
	
	
rule yodasProtector10xAshkbizDanehkar
{
strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack038betaDwing
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule AINEXEv21
{
strings:
		$a0 = { A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8 36 A3 ?? ?? 05 ?? ?? 36 A3 ?? ?? 2E A1 ?? ?? 8A D4 B1 04 D2 EA FE C9 }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePackV121build0909Method2bagie
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 8A 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 }

condition:
		$a0 at entrypoint
}
	
	
rule AppProtectorSilentTeam
{
strings:
		$a0 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A }
	$a1 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A 54 68 69 73 20 69 73 20 53 50 61 6B 65 64 20 41 70 70 6C 69 63 61 74 69 6F 6E 0D 0A 53 50 41 4B 20 63 6F 6D 70 72 69 6D 61 74 69 6F 6E 20 73 79 73 74 65 6D 20 69 73 20 AE 53 69 6C 65 6E 74 20 54 65 61 6D 99 0D 0A 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED 76 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 E8 01 00 00 00 9A 59 8D 95 C8 22 40 00 E8 01 00 00 00 69 58 66 BF 4D 4A E8 BF 01 00 00 8D 52 F9 E8 01 00 00 00 E8 5B 68 CC FF E2 9A FF E4 69 FF A5 E4 24 40 00 E9 E8 B9 FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PseudoSigner02PEProtect09
{
strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule PowerBASICWin70x
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 0F 85 DB 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VMProtectV1XPolyTech
{
strings:
		$a0 = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }

condition:
		$a0
}
	
	
rule ICrypt10byBuGGz
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 70 3B 00 10 E8 3C FA FF FF 33 C0 55 68 6C 3C 00 10 64 FF 30 64 89 20 6A 0A 68 7C 3C 00 10 A1 50 56 00 10 50 E8 D8 FA FF FF 8B D8 53 A1 50 56 00 10 50 E8 0A FB FF FF 8B F8 53 A1 50 56 00 10 50 E8 D4 FA FF FF 8B }
	$a1 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 70 3B 00 10 E8 3C FA FF FF 33 C0 55 68 6C 3C 00 10 64 FF 30 64 89 20 6A 0A 68 7C 3C 00 10 A1 50 56 00 10 50 E8 D8 FA FF FF 8B D8 53 A1 50 56 00 10 50 E8 0A FB FF FF 8B F8 53 A1 50 56 00 10 50 E8 D4 FA FF FF 8B D8 53 E8 D4 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 64 56 00 10 E8 25 F6 FF FF B8 64 56 00 10 E8 13 F6 FF FF 8B CF 8B D6 E8 E6 FA FF FF 53 E8 90 FA FF FF 8D 4D EC BA 8C 3C 00 10 A1 64 56 00 10 E8 16 FB FF FF 8B 55 EC B8 64 56 00 10 E8 C5 F4 FF FF B8 64 56 00 10 E8 DB F5 FF FF E8 56 FC FF FF 33 C0 5A 59 59 64 89 10 68 73 3C 00 10 8D 45 EC E8 4D F4 FF FF C3 E9 E3 EE FF FF EB F0 5F 5E 5B E8 4D F3 FF FF 00 53 45 54 ?? ?? ?? ?? 00 FF FF FF FF 08 00 00 00 76 6F 74 72 65 63 6C 65 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PEPackv099
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }

condition:
		$a0 at entrypoint
}
	
	
rule PENightMarev13
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCBasicNET
{
strings:
		$a0 = { FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxQuake518
{
strings:
		$a0 = { 1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81 }

condition:
		$a0 at entrypoint
}
	
	
rule PeNinjaDzAkRAkerTNT
{
strings:
		$a0 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	$a1 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule WWPACKv305c4UnextractableVirusShield
{
strings:
		$a0 = { 03 05 40 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium13013ObsidiumSoftware
{
strings:
		$a0 = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 }
	$a1 = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ASProtect123RC4build0807dllAlexeySolodovnikovh
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule PackItBitchV10archphaseSignbyfly
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule MetrowerksCodeWarriorv20Console
{
strings:
		$a0 = { 55 89 E5 55 B8 FF FF FF FF 50 50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

condition:
		$a0
}
	
	
rule tElockv090
{
strings:
		$a0 = { E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinv07Cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 88 39 40 00 8B 42 3C 03 C2 89 85 92 39 40 00 EB 01 DB 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D A6 39 40 00 53 8F 85 4A 38 40 00 BB ?? 00 00 00 B9 EC 0A 00 00 8D BD 36 3A 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 56 44 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 B3 5F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D 99 39 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EPv20
{
strings:
		$a0 = { 6A ?? 60 E9 01 01 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXShit006
{
strings:
		$a0 = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV130XObsidiumSoftwareSignbyfly
{
strings:
		$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B ?? ?? ?? EB 04 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 }

condition:
		$a0 at entrypoint
}
	
	
	
	
rule RCryptor16cbyVaskaUsArsign210320072225
{
strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 40 A1 14 13 B8 00 10 14 13 3D 24 C0 14 13 74 06 80 30 F2 40 EB F3 B8 8C 20 18 13 3D B9 27 18 13 74 06 80 30 E8 40 EB F3 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule SimpleUPXCryptorV3042005MANtiCORE
{
strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? ?? ?? E2 FA 61 68 ?? ?? ?? ?? C3 }

condition:
		$a0 at entrypoint
}
	
	
rule WinRAR32bitSFXModule
{
strings:
		$a0 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV2609JititSignbyfly
{
strings:
		$a0 = { E8 00 00 00 00 58 BB AD 19 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 1C 00 00 68 80 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 }

condition:
		$a0 at entrypoint
}
	
	
rule iPBProtect013017forgot
{
strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePack12build3009Method2bagie
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 86 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule CrinklerV03V04RuneLHStubbeandAskeSimonChristensen
{
strings:
		$a0 = { B8 00 00 42 00 31 DB 43 EB 58 }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDoteV12SISTeamSignbyfly
{
strings:
		$a0 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 65 73 75 6D 65 54 68 72 65 61 64 00 00 29 03 53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 94 03 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 00 6B 03 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 00 00 A6 02 52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 CA 01 47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 62 00 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 26 00 43 68 61 72 4C 6F 77 65 72 41 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 5E 02 66 72 65 65 00 00 4C 02 66 63 6C 6F 73 65 00 00 DA 00 5F 66 69 6C 62 75 66 00 91 02 6D 61 6C 6C 6F 63 00 00 64 02 66 74 65 6C 6C 00 62 02 66 73 65 65 6B 00 57 02 66 6F 70 65 6E 00 C5 02 73 74 72 73 74 72 00 00 4D 53 56 43 52 54 2E 64 6C 6C 00 00 }

condition:
		$a0
}
	
	
rule DingBoysPElockPhantasmv10v11
{
strings:
		$a0 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }

condition:
		$a0 at entrypoint
}
	
	
rule WIBUKeyV410AWIBUSYSTEMSAGSignbyfly
{
strings:
		$a0 = { F7 05 ?? ?? ?? ?? FF 00 00 00 75 12 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02BorlandDelphiSetupModule
{
strings:
		$a0 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactV2XBitsumTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeStealth275aWebtoolMaster
{
strings:
		$a0 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 }
	$a1 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 90 60 90 E8 00 00 00 00 5D 81 ED F7 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 74 28 40 00 8B F7 AC }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule VxXPEH4768
{
strings:
		$a0 = { E8 ?? ?? 5B 81 ?? ?? ?? 50 56 57 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B8 01 00 50 B8 ?? ?? 50 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule PECrypt32v102
{
strings:
		$a0 = { E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01PESHiELD025Anorganix
{
strings:
		$a0 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9 }

condition:
		$a0 at entrypoint
}
	
	
rule NETDLLMicrosoft
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 44 6C 6C 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 ?? 00 00 FF 25 }

condition:
		$a0
}
	
	
rule MSLRH
{
strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 }
	$a1 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule BorlandDelphi3PortionsCopyrightc198397Borlandh
{
strings:
		$a0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 37 20 42 6F 72 6C 61 6E 64 00 }

condition:
		$a0
}
	
	
rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCx
{
strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack01xbetaDwing
{
strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv60
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 }
	$a1 = { 55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B }
	$a2 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 89 65 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF }

condition:
		$a0 or $a1 at entrypoint or $a2
}
	
	
rule MicroJoiner17coban2k
{
strings:
		$a0 = { BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule TurboPascalv201984
{
strings:
		$a0 = { 90 90 CD AB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 34 }

condition:
		$a0 at entrypoint
}
	
	
rule CelsiusCrypt21Z3r0
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 84 92 44 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 84 92 44 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D C4 92 44 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D AC 92 44 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 77 C2 00 00 90 90 90 90 90 90 90 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }
	$a1 = { 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule Armadillov260
{
strings:
		$a0 = { 55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov261
{
strings:
		$a0 = { 55 8B EC 6A FF 68 28 ?? ?? ?? 68 E4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 0C }

condition:
		$a0 at entrypoint
}
	
	
rule VPackerttuiSignbyfly
{
strings:
		$a0 = { 89 C6 C7 45 E0 01 00 00 00 F7 03 00 00 FF FF 75 18 0F B7 03 50 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 EB 13 53 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 83 C7 04 FF 45 E0 4E 75 C4 8B F3 83 3E 00 75 88 8B 45 E4 8B 40 10 03 45 DC 8B 55 14 83 C2 20 89 02 68 00 80 00 00 6A 00 8B 45 D4 50 FF 55 EC 8B 55 DC 8B 42 3C 03 45 DC 83 C0 04 8B D8 83 C3 14 8D 45 E0 50 6A 40 68 00 10 00 00 52 FF 55 E8 8D 43 60 }

condition:
		$a0
}
	
	
rule tElock099SpecialBuildheXerforgot
{
strings:
		$a0 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 }

condition:
		$a0
}
	
	
rule hmimysPacker10
{
strings:
		$a0 = { E8 BA 00 00 00 03 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RatPackerGluestub
{
strings:
		$a0 = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }
	$a1 = { 40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule Upackv039finalDwingh
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule CreateInstallv200335
{
strings:
		$a0 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 00 50 FF 15 E0 80 40 00 8B 0D 00 50 40 00 E8 68 FF FF FF B9 40 0D 03 00 89 44 24 14 E8 5A FF FF FF 68 00 02 00 00 8B 2D D0 80 40 00 89 44 24 1C 8D 44 24 20 50 53 FF D5 8D 4C 24 1C 53 68 00 00 00 80 8B 3D CC 80 40 00 6A 03 53 6A 03 68 00 00 00 80 51 FF D7 8B F0 53 8D 44 24 14 8B 0D 00 50 40 00 8B 54 24 18 50 51 52 56 FF 15 C8 80 40 00 85 C0 0F 84 40 02 00 00 8B 15 00 50 40 00 3B 54 24 10 0F 85 30 02 00 00 6A FF A1 04 50 40 00 2B D0 8B 4C 24 18 03 C8 E8 9F FE FF FF 3B 05 10 50 40 00 0F 85 10 02 00 00 56 FF }

condition:
		$a0
}
	
	
rule ThinstallV2736JititSignbyfly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB F3 1C 00 00 2B C3 50 68 00 00 40 00 68 00 26 00 00 68 CC 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_UnknownDLLSignbyhot_UNP
{
strings:
		$a0 = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02 }

condition:
		$a0 at entrypoint
}
	
	
rule ExactAudioCopy
{
strings:
		$a0 = { E8 ?? ?? ?? 00 31 ED 55 89 E5 81 EC ?? 00 00 00 8D BD ?? FF FF FF B9 ?? 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SPECb3
{
strings:
		$a0 = { 5B 53 50 45 43 5D E8 ?? ?? ?? ?? 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualBasic50
{
strings:
		$a0 = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule MicrosoftVisualC80
{
strings:
		$a0 = { 48 83 EC 28 E8 ?? ?? 00 00 48 83 C4 28 E9 ?? ?? FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC }
	$a1 = { 83 3D ?? ?? ?? ?? 00 74 1A 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 59 74 0B FF 74 24 04 FF 15 ?? ?? ?? ?? 59 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 59 59 75 54 56 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 8B C6 BF }
	$a2 = { 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 }

condition:
		$a0 at entrypoint or $a1 or $a2 at entrypoint
}
	
	
rule PseudoSigner01MicrosoftVisualBasic5060Anorganix
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXModifiedStubbFarbrauschConsumerConsulting
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC }
	$a1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 C0 31 DB 31 C9 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 89 D8 E2 D9 8D BE ?? ?? ?? ?? 8B 07 09 C0 74 45 8B 5F 04 8D 84 30 ?? ?? ?? ?? 01 F3 50 83 C7 08 FF 96 ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 ?? ?? ?? ?? 61 E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule E2CbyDoP
{
strings:
		$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? FC 57 F3 A5 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule SVKProtectorv111
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }

condition:
		$a0 at entrypoint
}
	
	
rule CICryptV01FearlesS
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 }

condition:
		$a0 at entrypoint
}
	
	
rule PCShrinkerv071
{
strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }

condition:
		$a0 at entrypoint
}
	
	
rule Petite21
{
strings:
		$a0 = { 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 }

condition:
		$a0
}
	
	
rule PatchCreationWizard12MemoryPatch
{
strings:
		$a0 = { 6A 00 E8 9B 02 00 00 A3 7A 33 40 00 6A 00 68 8E 10 40 00 6A 00 6A 01 50 E8 B5 02 00 00 68 5A 31 40 00 68 12 31 40 00 6A 00 6A 00 6A 04 6A 01 6A 00 6A 00 68 A2 30 40 00 6A 00 E8 51 02 00 00 85 C0 74 31 FF 35 62 31 40 00 6A 00 6A 30 E8 62 02 00 00 E8 0B 01 }

condition:
		$a0
}
	
	
rule PIRITv15
{
strings:
		$a0 = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule PEBundlev20b5v23
{
strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD }

condition:
		$a0 at entrypoint
}
	
	
rule UnpackedBSSFXArchivev19
{
strings:
		$a0 = { 1E 33 C0 50 B8 ?? ?? 8E D8 FA 8E D0 BC ?? ?? FB B8 ?? ?? CD 21 3C 03 73 }

condition:
		$a0 at entrypoint
}
	
	
rule HPA
{
strings:
		$a0 = { E8 ?? ?? 5E 8B D6 83 ?? ?? 83 ?? ?? 06 0E 1E 0E 1F 33 FF 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv039finalSignbyhot_UNP
{
strings:
		$a0 = { 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 }
	$a1 = { FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF }

condition:
		$a0 or $a1
}
	
	
rule Armadillov310
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 44 00 33 F6 56 E8 72 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 3D 13 00 00 FF 15 30 40 44 00 A3 84 B7 44 00 E8 FB 11 00 00 A3 E0 A1 44 00 E8 A4 0F 00 00 E8 E6 0E 00 00 E8 4E F6 FF FF 89 75 D0 8D 45 A4 50 FF 15 38 40 44 00 E8 77 0E 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 7C 41 44 00 50 E8 49 D4 FE FF 89 45 A0 50 E8 3C F6 FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 B5 0C 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 2E F6 FF FF 83 3D E8 A1 44 00 01 75 05 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02NorthStarPEShrinker13
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack012betaDwing
{
strings:
		$a0 = { BE 48 01 40 00 AD ?? ?? ?? A5 ?? C0 33 C9 ?? ?? ?? ?? ?? ?? ?? F3 AB ?? ?? 0A ?? ?? ?? ?? AD 50 97 51 ?? 87 F5 58 8D 54 86 5C ?? D5 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B6 5F FF C1 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2xxmaxcompressedresourceswwwstrongbitcom
{
strings:
		$a0 = { 55 8B EC 83 C4 EC FC 53 57 56 89 45 FC 89 55 F8 89 C6 89 D7 66 81 3E 4A 43 0F 85 23 01 00 00 83 C6 0A C7 45 F4 08 00 00 00 31 DB BA 00 00 00 80 43 31 C0 E8 11 01 00 00 73 0E 8B 4D F0 E8 1F 01 00 00 02 45 EF AA EB E9 E8 FC 00 00 00 0F 82 97 00 00 00 E8 F1 }

condition:
		$a0 at entrypoint
}
	
	
rule SymantecWinFaxPRO75Coverpage
{
strings:
		$a0 = { 0C BD 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C0 06 80 }

condition:
		$a0
}
	
	
rule VProtectorvcasm
{
strings:
		$a0 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F }
	$a1 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 }
	$a2 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C }
	$a3 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C 00 00 00 00 }
	$a4 = { 00 00 00 00 55 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 64 69 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 6C 65 61 73 65 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 }

condition:
		$a0 or $a1 at entrypoint or $a2 or $a3 or $a4
}
	
	
rule Spalsher1030Amok
{
strings:
		$a0 = { 9C 60 8B 44 24 24 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PEQuakeV006forgat
{
strings:
		$a0 = { E8 A5 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule XPackv142
{
strings:
		$a0 = { 72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3 }

condition:
		$a0
}
	
	
rule UCEXEv23v24
{
strings:
		$a0 = { 50 1E 0E 1F FC 33 F6 E8 ?? ?? 16 07 33 F6 33 FF B9 ?? ?? F3 A5 06 B8 ?? ?? 50 CB }

condition:
		$a0 at entrypoint
}
	
	
rule W32JeefoPEFileInfector
{
strings:
		$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 ?? ?? ?? FF D0 E8 ?? ?? ?? ?? C9 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSplitter13SplitCryptMethodBillPrisonerTPOC
{
strings:
		$a0 = { 15 10 05 23 14 56 57 57 48 12 0B 16 66 66 66 66 66 66 66 66 66 02 C7 56 66 66 66 ED 26 6A ED 26 6A ED 66 E3 A6 69 E2 39 64 66 66 ED 2E 56 E6 5F 0D 12 61 E6 5F 2D 12 64 8D 81 E6 1F 6A 55 12 64 8D B9 ED 26 7E A5 33 ED 8A 8D 69 21 03 12 36 14 09 05 27 02 02 14 03 15 15 27 ED 2B 6A ED 13 6E ED B8 65 10 5A EB 10 7E EB 10 06 ED 50 65 95 30 ED 10 46 65 95 55 B4 ED A0 ED 50 65 95 37 ED 2B 6A EB DF AB 76 26 66 3F DF 68 66 66 66 9A 95 C0 6D AF 13 64 }
	$a1 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 B9 ?? ?? ?? ?? 8D 85 1D 10 40 00 80 30 66 40 E2 FA 8F 98 67 66 66 ?? ?? ?? ?? ?? ?? ?? 66 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule PseudoSigner01PackMaster10PEXClone
{
strings:
		$a0 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote12BetaDemoSISTeam
{
strings:
		$a0 = { 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74 2F 68 04 01 00 00 68 B0 21 60 00 6A 00 FF 15 08 10 60 00 E8 29 FF FF FF 50 68 88 10 60 00 68 78 10 60 00 68 B0 21 60 00 E8 A4 FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 90 90 90 90 90 90 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule Morphine27Holy_FatherRatter29A
{
strings:
		$a0 = { 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule EXECryptor224StrongbitSoftCompleteDevelopmenth1
{
strings:
		$a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor224StrongbitSoftCompleteDevelopmenth2
{
strings:
		$a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 ?? 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSRunTimeLibrary1987
{
strings:
		$a0 = { B4 30 CD 21 3C 02 73 ?? 9A ?? ?? ?? ?? B8 ?? ?? 50 9A ?? ?? ?? ?? 92 }

condition:
		$a0 at entrypoint
}
	
	
rule AdlibSampleAudiofile
{
strings:
		$a0 = { 47 4F 4C 44 20 53 41 4D 50 4C 45 }

condition:
		$a0
}
	
	
rule PackMasterv10
{
strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
	$a1 = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PEiDBundlev104BoBBobSoft
{
strings:
		$a0 = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

condition:
		$a0 at entrypoint
}
	
	
rule DBPEv153
{
strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandCforWin321999
{
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 }
	$a1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule BorlandCforWin321994
{
strings:
		$a0 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 83 ?? ?? ?? ?? 75 ?? 57 51 33 C0 BF }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandCforWin321995
{
strings:
		$a0 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner152Stubengine16GlOFF
{
strings:
		$a0 = { E8 46 FD FF FF 50 E8 0C 00 00 00 FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule XMImusicfile
{
strings:
		$a0 = { 46 4F 52 4D ?? ?? ?? ?? 58 4D 49 44 }

condition:
		$a0
}
	
	
rule XMmusicfile
{
strings:
		$a0 = { 45 78 74 65 6E 64 65 64 20 4D 6F 64 75 6C 65 3A }

condition:
		$a0
}
	
	
rule FreePascal104Win32BercziGaborPierreMullerPeterVreman
{
strings:
		$a0 = { 55 89 E5 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 55 31 ED 89 E0 A3 ?? ?? ?? ?? 66 8C D5 89 2D ?? ?? ?? ?? DB E3 D9 2D ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? 5D E8 ?? ?? ?? ?? C9 C3 }

condition:
		$a0
}
	
	
rule ASProtectv12AlexeySolodovnikovh1
{
strings:
		$a0 = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 ?? ?? ?? 00 }

condition:
		$a0
}
	
	
rule ObsidiumV125ObsidiumSoftware
{
strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule ANDpakk2006byDmitryquotANDquotAndreev
{
strings:
		$a0 = { 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }

condition:
		$a0 at entrypoint
}
	
	
rule PENightMare2Beta
{
strings:
		$a0 = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

condition:
		$a0 at entrypoint
}
	
	
rule MinGWGCC3x
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? 55 }

condition:
		$a0 at entrypoint
}
	
	
rule PEPaCK10CCopyright1998byANAKiNh
{
strings:
		$a0 = { C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 2D 3D FE 20 50 45 2D 50 41 43 4B 20 76 31 2E 30 20 2D FE 2D 20 28 43 29 20 43 6F 70 }

condition:
		$a0
}
	
	
rule PESpin13xCyberbob
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 }

condition:
		$a0 at entrypoint
}
	
	
rule VxVirusConstructorIVPbased
{
strings:
		$a0 = { E9 ?? ?? E8 ?? ?? 5D ?? ?? ?? ?? ?? 81 ED ?? ?? ?? ?? ?? ?? E8 ?? ?? 81 FC ?? ?? ?? ?? 8D ?? ?? ?? BF ?? ?? 57 A4 A5 }

condition:
		$a0 at entrypoint
}
	
	
rule Reg2Exe224byJanVorel
{
strings:
		$a0 = { 6A 00 E8 CF 20 00 00 A3 F4 45 40 00 E8 CB 20 00 00 6A 0A 50 6A 00 FF 35 F4 45 40 00 E8 07 00 00 00 50 E8 BB 20 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 F8 45 40 00 E8 06 19 00 00 83 C4 0C 8B 44 24 04 A3 FC 45 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 }
	$a1 = { 6A 00 E8 CF 20 00 00 A3 F4 45 40 00 E8 CB 20 00 00 6A 0A 50 6A 00 FF 35 F4 45 40 00 E8 07 00 00 00 50 E8 BB 20 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 F8 45 40 00 E8 06 19 00 00 83 C4 0C 8B 44 24 04 A3 FC 45 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 8C 20 00 00 A3 F8 45 40 00 E8 02 20 00 00 E8 32 1D 00 00 E8 20 19 00 00 E8 A3 16 00 00 68 01 00 00 00 68 38 46 40 00 68 00 00 00 00 8B 15 38 46 40 00 E8 71 4F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 4F 00 00 FF 35 48 41 40 00 B8 00 01 00 00 E8 9D 15 00 00 8D 0D 1C 46 40 00 5A E8 82 16 00 00 68 00 01 00 00 FF 35 1C 46 40 00 E8 24 20 00 00 A3 24 46 40 00 FF 35 48 41 40 00 FF 35 24 46 40 00 FF 35 1C 46 40 00 E8 DC 10 00 00 8D 0D 14 46 40 00 5A E8 4A 16 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule SpecialEXEPaswordProtector101EngPavolCerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 00 00 8D 95 C6 77 00 00 8D 8D FF 77 00 00 55 68 00 20 00 00 51 52 6A 00 FF 95 04 7A 00 00 5D 6A 00 FF 95 FC 79 00 00 8D 8D 60 78 00 00 8D 95 85 01 00 00 55 68 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SVKProtectorv13xEngPavolCerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 0C 61 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 18 61 00 00 5D 6A FF FF 95 10 61 00 00 44 65 62 75 67 67 65 72 20 6F 72 20 74 6F 6F 6C 20 66 6F 72 20 6D 6F 6E 69 74 6F 72 69 6E 67 20 64 65 74 65 63 74 65 64 21 21 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXcrypterarchphaseNWC
{
strings:
		$a0 = { BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule CAN2EXEv001
{
strings:
		$a0 = { 26 8E 06 ?? ?? B9 ?? ?? 33 C0 8B F8 F2 AE E3 ?? 26 38 05 75 ?? EB ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftCforWindows1
{
strings:
		$a0 = { 33 ED 55 9A ?? ?? ?? ?? 0B C0 74 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftCforWindows2
{
strings:
		$a0 = { 8C D8 ?? 45 55 8B EC 1E 8E D8 57 56 89 }

condition:
		$a0 at entrypoint
}
	
	
rule FishPEV10Xhellfish
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 ?? ?? 00 00 ?? ?? ?? ?? 00 00 02 00 00 00 A0 00 00 18 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule FSG120EngdulekxtBorlandDelphiBorlandC
{
strings:
		$a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }

condition:
		$a0
}
	
	
rule PECrypter
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D EB 26 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv051
{
strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

condition:
		$a0 at entrypoint
}
	
	
rule LY_WGKXwwwszleyucom
{
strings:
		$a0 = { 4D 79 46 75 6E 00 62 73 }

condition:
		$a0
}
	
	
rule ASProtect13321RegisteredAlexeySolodovnikov
{
strings:
		$a0 = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftRIncrementalLinkerVersion5128078MASMTASM
{
strings:
		$a0 = { 6A 00 68 00 30 40 00 68 1E 30 40 00 6A 00 E8 0D 00 00 00 6A 00 E8 00 00 00 00 FF 25 00 20 40 00 FF 25 08 20 40 }

condition:
		$a0
}
	
	
rule CryptComv11
{
strings:
		$a0 = { BF ?? ?? 57 BE ?? ?? ?? B9 ?? ?? F3 A4 C3 8B ?? ?? ?? 8B ?? ?? ?? BF ?? ?? 57 BE ?? ?? ?? AD 33 C2 AB E2 ?? C3 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMicrosoftVisualC4xLCCWin321x
{
strings:
		$a0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }

condition:
		$a0 at entrypoint
}
	
	
rule GoatsPEMutilator16
{
strings:
		$a0 = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a1 = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0F 53 0F DE 0F 55 0F 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule UPXv062DLL
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 58 }

condition:
		$a0 at entrypoint
}
	
	
rule dePACKdeNULL
{
strings:
		$a0 = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? 00 00 E8 ?? 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeNeolite20emadiciush
{
strings:
		$a0 = { E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 39 39 39 20 4E 65 6F 57 6F 72 78 20 49 6E 63 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 31 39 39 39 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 00 00 00 00 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote10DemoSISTeam
{
strings:
		$a0 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 }
	$a1 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 65 73 75 6D 65 54 68 72 65 61 64 00 00 29 03 53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 94 03 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 00 6B 03 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 00 00 A6 02 52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 CA 01 47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 62 00 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 DC 01 4D 65 73 73 61 67 65 42 6F 78 41 00 26 00 43 68 61 72 4C 6F 77 65 72 41 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 C5 02 73 74 72 73 74 72 00 00 91 02 6D 61 6C 6C 6F 63 00 00 5E 02 66 72 65 65 00 00 4C 02 66 63 6C 6F 73 65 00 00 DA 00 5F 66 69 6C 62 75 66 00 64 02 66 74 65 6C 6C 00 62 02 66 73 65 65 6B 00 57 02 66 6F 70 65 6E 00 49 00 5F 5F 43 78 78 46 72 61 6D 65 48 61 6E 64 6C 65 72 00 4D 53 56 43 52 54 2E 64 6C 6C 00 00 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule LCCWin32DLL
{
strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptorv1401
{
strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 }

condition:
		$a0 at entrypoint
}
	
	
rule MSRunTimeLibrary199010
{
strings:
		$a0 = { E8 ?? ?? 2E FF 2E ?? ?? BB ?? ?? E8 ?? ?? CB }

condition:
		$a0 at entrypoint
}
	
	
rule Reg2Exe220221byJanVorel
{
strings:
		$a0 = { 6A 00 E8 7D 12 00 00 A3 A0 44 40 00 E8 79 12 00 00 6A 0A 50 6A 00 FF 35 A0 44 40 00 E8 0F 00 00 00 50 E8 69 12 00 00 CC CC CC CC CC CC CC CC CC 68 2C 02 00 00 68 00 00 00 00 68 B0 44 40 00 E8 3A 12 00 00 83 C4 0C 8B 44 24 04 A3 B8 44 40 00 68 00 00 00 00 }
	$a1 = { 6A 00 E8 7D 12 00 00 A3 A0 44 40 00 E8 79 12 00 00 6A 0A 50 6A 00 FF 35 A0 44 40 00 E8 0F 00 00 00 50 E8 69 12 00 00 CC CC CC CC CC CC CC CC CC 68 2C 02 00 00 68 00 00 00 00 68 B0 44 40 00 E8 3A 12 00 00 83 C4 0C 8B 44 24 04 A3 B8 44 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 32 12 00 00 A3 B0 44 40 00 68 F4 01 00 00 68 BC 44 40 00 FF 35 B8 44 40 00 E8 1E 12 00 00 B8 BC 44 40 00 89 C1 8A 30 40 80 FE 5C 75 02 89 C1 80 FE 00 75 F1 C6 01 00 E8 EC 18 00 00 E8 28 16 00 00 E8 4A 12 00 00 68 00 FA 00 00 68 08 00 00 00 FF 35 B0 44 40 00 E8 E7 11 00 00 A3 B4 44 40 00 8B 15 D4 46 40 00 E8 65 0A 00 00 BB 00 00 10 00 B8 01 00 00 00 E8 72 0A 00 00 74 09 C7 00 01 00 00 00 83 C0 04 A3 D4 46 40 00 FF 35 B4 44 40 00 E8 26 05 00 00 8D 0D B8 46 40 00 5A E8 CF 0F 00 00 FF 35 B4 44 40 00 FF 35 B8 46 40 00 E8 EE 06 00 00 8D 0D B4 46 40 00 5A E8 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PELockNTv201
{
strings:
		$a0 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtectorV10bAshkbizDanehkarSignbyfly
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01 ?? AC }

condition:
		$a0 at entrypoint
}
	
	
rule PELockNTv204
{
strings:
		$a0 = { EB ?? CD ?? ?? ?? ?? ?? CD ?? ?? ?? ?? ?? EB ?? EB ?? EB ?? EB ?? CD ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 50 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtector1xRandyLi
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 }
	$a1 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 7B 03 00 00 03 C8 74 C4 75 C2 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Obsidium13017Obsidiumsoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
	$a1 = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 4F 26 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PESpin13betaCyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

condition:
		$a0
}
	
	
rule PluginToExev101BoBBobSoft
{
strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A 40 FF 95 A9 41 40 00 89 85 69 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 A9 41 40 00 89 47 1C C7 07 58 00 00 00 C7 47 20 00 08 00 00 C7 47 18 01 00 00 00 C7 47 34 04 10 88 00 8D 8D B9 40 40 00 89 4F 0C 8D 8D DB 40 40 00 89 4F 30 FF B5 69 40 40 00 FF 95 95 41 40 00 FF 77 1C 8F 85 75 40 40 00 8B 9D 6D 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 75 40 40 00 6A 00 81 C3 ?? ?? 00 00 FF D3 83 C4 10 83 BD 71 40 40 00 00 74 10 FF 77 1C FF 95 AD 41 40 00 57 FF 95 AD 41 40 00 6A 00 FF 95 9D 41 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV1304ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 ?? 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1341ObsidiumSoftware
{
strings:
		$a0 = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 }
	$a1 = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule eXcaliburv103forgotush
{
strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 20 45 78 63 61 6C 69 62 75 72 20 28 63 29 20 62 79 20 66 6F 72 67 6F 74 2F 75 53 2F 44 46 43 47 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }
	$a1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 20 45 78 63 61 6C 69 62 75 72 20 28 63 29 20 62 79 20 66 6F 72 67 6F 74 2F 75 53 2F 44 46 43 47 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 0D 0A 60 9C 9C 6A 63 73 0B EB 02 E8 E8 E8 06 00 00 00 E8 E8 73 F7 E8 E8 83 C4 04 EB 02 E8 E8 FF 0C 24 71 01 E8 79 E0 7A 01 E8 83 C4 04 9D EB 01 E8 E8 01 00 00 00 E9 5D 81 ED AE 28 40 00 9C 6A 63 73 0B EB 02 69 69 E8 06 00 00 00 69 69 73 F7 69 69 83 C4 04 EB 02 69 69 FF 0C 24 71 01 69 79 E0 7A 01 69 83 C4 04 9D EB 01 69 E8 E7 02 00 00 E8 9C 6A 63 73 0B EB 02 69 69 E8 06 00 00 00 69 69 73 F7 69 69 83 C4 04 EB 02 69 69 FF 0C 24 71 01 69 79 E0 7A 01 69 83 C4 04 9D EB 01 69 E8 B4 02 00 00 E8 60 E8 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule PseudoSigner01PackMaster10PEXCloneAnorganix
{
strings:
		$a0 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FF FF E9 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallV2736Jitit
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB F3 1C 00 00 2B C3 50 68 00 00 40 00 68 00 26 00 00 68 CC 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule RLP073betaap0xh
{
strings:
		$a0 = { 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8 42 31 40 00 BB 41 30 40 00 2B C3 03 C5 33 D2 8A 10 40 B9 ?? ?? 00 00 8B F9 30 10 8A 10 40 49 75 F8 64 EF 86 3D 30 00 00 0F B9 FF 4B 89 52 5C 4C BD 77 C2 0C CE 88 4E 2D E8 00 00 00 5D 0D DB 5E 56 }

condition:
		$a0
}
	
	
rule FixupPak120
{
strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 }

condition:
		$a0
}
	
	
rule RARConfigurationfile
{
strings:
		$a0 = { 52 41 52 20 43 4F 4E 46 49 47 }

condition:
		$a0
}
	
	
rule InstallShieldCustom
{
strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? 41 00 8B F0 85 F6 75 08 6A FF FF 15 ?? ?? 41 00 8A 06 57 8B 3D ?? ?? 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B }

condition:
		$a0 at entrypoint
}
	
	
rule Petitevafterv14
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8D ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 83 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeToolsv21EncruptorbyDISMEMBER
{
strings:
		$a0 = { E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74 }

condition:
		$a0 at entrypoint
}
	
	
rule NJoy12NEX
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 A4 32 40 00 E8 E8 F1 FF FF 6A 00 68 54 2A 40 00 6A 0A 6A 00 E8 A8 F2 FF FF E8 C7 EA FF FF 8D 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinv0b
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 26 E8 01 00 00 00 EA 5A 33 C9 8B 95 68 20 40 00 8B 42 3C 03 C2 89 85 76 20 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D 8A 20 40 00 8B 59 24 03 DA 8B 1B 89 9D 8E 20 40 00 53 8F 85 E2 1F 40 00 8D 85 92 20 40 00 6A 0C 5B 6A 17 59 30 0C 03 02 CB 4B 75 F8 40 8D 9D 41 8F 4E 00 50 53 81 2C 24 01 78 0E 00 FF B5 8A 20 40 00 C3 92 EB 15 68 BB ?? 00 00 00 B9 90 08 00 00 8D BD FF 20 40 00 4F 30 1C 39 FE CB E2 F9 68 1D 01 00 00 59 8D BD 2F 28 40 00 C0 0C 39 02 E2 FA 68 A0 20 40 00 50 01 6C 24 04 E8 BD 09 00 00 33 C0 0F 84 C0 08 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VXTibsZhelatinStormWormvariant
{
strings:
		$a0 = { FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule NSPack3xLiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }

condition:
		$a0 at entrypoint
}
	
	
rule SVKPv132PavolCervenh
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 0C 61 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 18 61 00 00 5D 6A FF FF 95 10 61 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv25RetailBitsumTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv029Betav031BetaSignbyhot_UNP
{
strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }

condition:
		$a0
}
	
	
rule PseudoSigner01BorlandDelphi30
{
strings:
		$a0 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule NFOv10
{
strings:
		$a0 = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C }

condition:
		$a0 at entrypoint
}
	
	
rule PMODEWv112116121133DOSextender
{
strings:
		$a0 = { FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4 }

condition:
		$a0 at entrypoint
}
	
	
rule Anti007V10V2XNsPacKPrivate
{
strings:
		$a0 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 45 78 69 74 }

condition:
		$a0 at entrypoint
}
	
	
rule AaseCrypterbysantasdad
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 B8 A0 3E 00 10 E8 93 DE FF FF 68 F8 42 00 10 E8 79 DF FF FF 68 00 43 00 10 68 0C 43 00 10 E8 42 DF FF FF 50 E8 44 DF FF FF A3 98 66 00 10 83 3D 98 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 1C 43 00 10 6A 00 E8 4B DF FF FF 68 2C 43 00 }
	$a1 = { 55 8B EC 83 C4 F0 53 B8 A0 3E 00 10 E8 93 DE FF FF 68 F8 42 00 10 E8 79 DF FF FF 68 00 43 00 10 68 0C 43 00 10 E8 42 DF FF FF 50 E8 44 DF FF FF A3 98 66 00 10 83 3D 98 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 1C 43 00 10 6A 00 E8 4B DF FF FF 68 2C 43 00 10 68 0C 43 ?? ?? ?? ?? DF FF FF 50 E8 0E DF FF FF A3 94 66 00 10 83 3D 94 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 38 43 00 10 6A 00 E8 15 DF FF FF 68 48 43 00 10 68 0C 43 00 10 E8 D6 DE FF FF 50 E8 D8 DE FF FF A3 A0 66 00 10 83 3D A0 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 58 43 00 10 6A 00 E8 DF DE FF FF 68 6C 43 00 10 68 0C 43 00 10 E8 A0 DE FF FF 50 E8 A2 DE FF FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule CreateInstall200335
{
strings:
		$a0 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 }

condition:
		$a0
}
	
	
rule yodasProtectorv1032exescrcomAshkbizDanehkarh
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 BF A4 42 00 81 E9 8E 74 42 00 8B D5 81 C2 8E 74 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 63 29 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePEBundle023xemadicius
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 }

condition:
		$a0
}
	
	
rule EPExEPackV14liteb26aHguTgluk
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallVirtualizationSuiteV3035V3043ThinstallCompanySignbyfly
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

condition:
		$a0 at entrypoint
}
	
	
rule EXE2COMLimited
{
strings:
		$a0 = { BE ?? ?? 8B 04 3D ?? ?? 74 ?? BA ?? ?? B4 09 CD 21 CD 20 }

condition:
		$a0 at entrypoint
}
	
	
rule VProtectorV10Evcasm
{
strings:
		$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01MicrosoftVisualC60DebugVersionAnorganix
{
strings:
		$a0 = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 10 01 90 90 90 90 90 90 90 90 E8 00 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Spalsherv10v30
{
strings:
		$a0 = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }

condition:
		$a0 at entrypoint
}
	
	
rule DJoinv07publicRC4encryptiondrmist
{
strings:
		$a0 = { C6 05 ?? ?? 40 00 00 C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePECrypt102emadicius
{
strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB }

condition:
		$a0
}
	
	
rule VProtectorV10Dvcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 CA 31 41 00 68 06 32 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

condition:
		$a0 at entrypoint
}
	
	
rule PEDiminisherV01Teraphy
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv305c4ExtrPasswcheckVirshield
{
strings:
		$a0 = { 03 05 C0 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCvxx
{
strings:
		$a0 = { 53 55 56 8B ?? ?? ?? 85 F6 57 B8 ?? ?? ?? ?? 75 ?? 8B ?? ?? ?? ?? ?? 85 C9 75 ?? 33 C0 5F 5E 5D 5B C2 }
	$a1 = { 55 8B EC 56 57 BF ?? ?? ?? ?? 8B ?? ?? 3B F7 0F }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RLPackV118BasicEditionaPLiborLZMAap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? 00 00 8D 9D ?? 02 00 00 33 FF E8 ?? 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakenSPack13emadicius
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 }

condition:
		$a0
}
	
	
rule PseudoSigner02DEF10
{
strings:
		$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 }

condition:
		$a0 at entrypoint
}
	
	
rule RSCsProcessPatcher14
{
strings:
		$a0 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 }

condition:
		$a0
}
	
	
rule Upackv036alphaSignbyhot_UNP
{
strings:
		$a0 = { AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0 }

condition:
		$a0
}
	
	
rule EncryptPEV22006710V220070411WFS
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SymantecWinFaxPRO83Coverpage
{
strings:
		$a0 = { 0C BD 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C0 06 6C }

condition:
		$a0
}
	
	
rule codeCrypter031Tibbar
{
strings:
		$a0 = { 50 58 53 5B 90 BB ?? ?? ?? 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

condition:
		$a0 at entrypoint
}
	
	
rule VIRUSIWormHybris
{
strings:
		$a0 = { EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15 }

condition:
		$a0
}
	
	
rule PEnguinCryptv10
{
strings:
		$a0 = { B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule PECrc32088ZhouJinYu
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv123b3v1241
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 08 }

condition:
		$a0 at entrypoint
}
	
	
rule Noodlecrypt2rsc
{
strings:
		$a0 = { EB 01 9A E8 76 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule CRYPToCRACksPEProtectorV092LukasFleischerSignbyfly
{
strings:
		$a0 = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv42
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? C7 }
	$a1 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RLPack120BasicEditionLZMAAp0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01PENightMare2BetaAnorganix
{
strings:
		$a0 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9 }

condition:
		$a0 at entrypoint
}
	
	
rule CreativeAudiofile
{
strings:
		$a0 = { 43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46 69 6C 65 }

condition:
		$a0
}
	
	
rule RLPackv118BasicDLLLZMAAp0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }

condition:
		$a0 at entrypoint
}
	
	
rule CrypKeyv5v6
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06 }

condition:
		$a0 at entrypoint
}
	
	
rule DOS32v33DOSExtenderandLoader
{
strings:
		$a0 = { 0E 1F FC 9C 5B 8B C3 80 F4 ?? 50 9D 9C 58 3A E7 75 ?? BA ?? ?? B4 09 CD 21 B4 4C CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule InnoSetupModulev109a
{
strings:
		$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule nPackV112502006BetaNEOxuinC
{
strings:
		$a0 = { 83 3D 04 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E ?? ?? ?? 2B 05 08 ?? ?? ?? A3 00 ?? ?? ?? E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 ?? ?? ?? C7 05 04 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule SunIconGraphicsformat
{
strings:
		$a0 = { 2F 2A 20 46 6F 72 6D 61 74 5F 76 65 72 73 69 6F 6E 3D 31 2C }

condition:
		$a0
}
	
	
rule FreePascal106
{
strings:
		$a0 = { C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00 }

condition:
		$a0
}
	
	
rule ObsidiumV1300ObsidiumSoftware
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 }
	$a1 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 }
	$a2 = { EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule PCryptv351
{
strings:
		$a0 = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule DEFv100Engbartxt
{
strings:
		$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo310
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 }

condition:
		$a0
}
	
	
rule yzpackV112UsAr
{
strings:
		$a0 = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 ?? ?? ?? ?? B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 E0 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ActiveMARKTM
{
strings:
		$a0 = { 79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2117StrongbitSoftCompleteDevelopmenth
{
strings:
		$a0 = { BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 }
	$a1 = { BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 D0 03 45 F4 8B 18 8B 7E 10 01 D7 03 7D F4 09 DB 0F 84 ?? 00 00 00 F7 C3 00 00 00 80 0F 85 04 00 00 00 8D 5C 13 02 81 E3 FF FF FF 7F 53 FF 75 F8 FF 15 9C ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 07 83 45 F4 04 E9 A6 FF FF FF }

condition:
		$a0 or $a1
}
	
	
rule EXE2COMEncryptedwithoutselfcheck
{
strings:
		$a0 = { B3 ?? B9 ?? ?? BE ?? ?? BF ?? ?? EB ?? 54 69 ?? ?? ?? ?? 03 ?? ?? 32 C3 AA 43 49 E3 ?? EB ?? BE ?? ?? 8B C6 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackAp0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 CD 09 00 00 89 85 14 0A 00 00 EB 14 60 FF B5 14 0A }
	$a1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 EB 09 00 00 89 85 3A 0A 00 00 EB 14 60 FF B5 3A 0A }
	$a2 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 0C 00 00 EB 03 0C 00 00 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 47 02 00 00 EB 03 15 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 9B 0A }
	$a3 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 CD 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 14 0A }
	$a4 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 3A 0A }
	$a5 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 ?? ?? ?? ?? EB 03 ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 9B 0A }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint or $a4 at entrypoint or $a5 at entrypoint
}
	
	
rule Petite14c199899IanLuckh
{
strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 72 04 03 7A 08 8B 0A F3 A5 83 C2 0C FC EB D4 8B 7A 08 03 F8 8B 5A 04 85 DB 74 13 52 53 57 03 02 50 E8 79 00 00 00 85 C0 74 30 5F 5F 58 5A 8B 4A 0C C1 F9 02 33 C0 F3 AB 8B 4A 0C 83 E1 03 F3 AA 83 C2 10 EB 9E 45 52 52 4F 52 21 00 43 6F 72 72 75 70 74 20 44 61 74 61 21 00 8B 64 24 24 8B 04 24 83 C4 26 8B D0 66 81 C2 7E 01 6A 10 8B D8 66 05 77 01 50 52 6A 00 03 1B FF 13 6A FF FF 53 08 56 57 8B 7C 24 0C 8B 74 24 10 8B 4C 24 14 C1 F9 02 F3 A5 8B 4C 24 14 83 E1 03 F3 A4 5F 5E C3 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinv04x
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B }

condition:
		$a0
}
	
	
rule MinGWv32xDll_mainCRTStartup
{
strings:
		$a0 = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 00 10 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasCrypter13AshkbizDanehkar
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 }
	$a1 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ThinstallEmbeddedV2717V2719Jitit
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 C1 FE FF FF E9 97 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D }

condition:
		$a0 at entrypoint
}
	
	
rule D1NS1GD1N
{
strings:
		$a0 = { 18 37 00 00 00 00 00 00 01 00 0A 00 00 00 18 00 00 80 00 00 00 00 ?? ?? 18 37 00 00 00 00 02 00 00 00 88 00 00 80 38 00 00 80 96 00 00 80 50 00 00 80 00 00 00 00 ?? ?? 18 37 00 00 00 00 00 00 01 00 00 00 00 00 68 00 00 00 00 00 00 00 ?? ?? 18 37 00 00 00 00 00 00 01 00 00 00 00 00 78 00 00 00 B0 F0 00 00 10 00 00 00 00 00 00 00 00 00 00 00 C0 F0 00 00 60 00 00 00 00 00 00 00 00 00 00 00 06 00 44 00 56 00 43 00 4C 00 41 00 4C 00 0B 00 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule SPECb2
{
strings:
		$a0 = { 55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMicrosoftVisualC6070ASM
{
strings:
		$a0 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }

condition:
		$a0 at entrypoint
}
	
	
rule Petite22c199899IanLuck
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv16xVaska
{
strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? C3 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV118BasicEditionLZMA430ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01MinGWGCC2xAnorganix
{
strings:
		$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov253
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Armadillov252
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? E0 ?? ?? ?? ?? 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 38 }
	$a1 = { 55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Armadillov251
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov250
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1331ObsidiumSoftware
{
strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPv073betaap0xh
{
strings:
		$a0 = { 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8 42 31 40 00 BB 41 30 40 00 2B C3 03 C5 33 D2 8A 10 40 B9 ?? ?? 00 00 8B F9 30 10 8A 10 40 49 75 F8 64 EF 86 3D 30 00 00 0F B9 FF 4B 89 52 5C 4C BD 77 C2 0C CE 88 4E 2D E8 00 00 00 5D 0D DB 5E 56 41 87 FC 0F F3 05 40 81 68 4B 93 71 40 BB 87 3C 40 40 8B 88 06 75 70 40 40 8B BB B3 43 C4 8F 93 2B F3 4A 88 06 07 30 F5 EA 2A 35 F0 4B 8A C3 07 C1 C6 02 C4 34 C0 74 74 32 02 C4 45 0B 3C 96 BE 0A 82 C3 DE 36 A9 7E 5A 51 A6 BC 63 A8 66 CB 30 58 20 8C CC 85 53 9F C1 E4 10 80 11 20 1E 48 D2 E8 F7 28 5C 26 89 5C 94 89 5A F8 1C 0B 74 7E 33 4E 9B 29 56 F2 2B 84 42 8A 95 16 76 64 08 7B 70 8F A0 0B A8 3A C1 C7 B5 3E D9 70 }

condition:
		$a0
}
	
	
rule ASProtectSKE23AlexeySolodovnikovh
{
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 E5 0B 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C }

condition:
		$a0
}
	
	
rule RLPackFullEdition117DLLaPLib
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 53 03 00 00 8D 9D 02 02 00 00 33 FF E8 ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 }

condition:
		$a0 at entrypoint
}
	
	
rule DIETv144v145f
{
strings:
		$a0 = { F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA ?? ?? 03 D0 52 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv098
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv099
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeMSVC60DLLemadiciush
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1258ObsidiumSoftware
{
strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 }
	$a1 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule FSGv110EngdulekxtMicrosoftVisualBasic5060
{
strings:
		$a0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv090
{
strings:
		$a0 = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv092
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }

condition:
		$a0 at entrypoint
}
	
	
rule XPack167com
{
strings:
		$a0 = { E9 53 00 FF FD FF FB FF F9 FF BC 03 00 8B E5 4C 4C C3 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv094
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 }

condition:
		$a0 at entrypoint
}
	
	
rule PeX099bartCrackPl
{
strings:
		$a0 = { E9 F5 ?? ?? ?? 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

condition:
		$a0 at entrypoint
}
	
	
rule XWDgraphicsformat
{
strings:
		$a0 = { 00 00 00 71 00 00 00 07 00 00 00 02 00 00 00 }

condition:
		$a0
}
	
	
rule Enigmaprotector110unregistered
{
strings:
		$a0 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 }
	$a1 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 E9 51 0B C4 80 BC 7E 35 09 37 E7 C9 3D C9 45 C9 4D 74 92 BA E4 E9 24 6B DF 3E 0E 38 0C 49 10 27 80 51 A1 8E 3A A3 C8 AE 3B 1C 35 }

condition:
		$a0 or $a1
}
	
	
rule AdFlt2
{
strings:
		$a0 = { 68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD }

condition:
		$a0 at entrypoint
}
	
	
rule FixupPakv120
{
strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 AC 0F B6 C0 03 D8 29 13 E2 FA EB BC 8D 85 ?? ?? 00 00 5D FF E0 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ARCSFXArchive
{
strings:
		$a0 = { 8C C8 8C DB 8E D8 8E C0 89 ?? ?? ?? 2B C3 A3 ?? ?? 89 ?? ?? ?? BE ?? ?? B9 ?? ?? BF ?? ?? BA ?? ?? FC AC 32 C2 8A D8 }

condition:
		$a0 at entrypoint
}
	
	
rule MoleBoxv230Teggo
{
strings:
		$a0 = { 42 04 E8 ?? ?? 00 00 A3 ?? ?? ?? 00 8B 4D F0 8B 11 89 15 ?? ?? ?? 00 ?? 45 FC A3 ?? ?? ?? 00 5F 5E 8B E5 5D C3 CC CC CC CC CC CC CC CC CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 20 61 58 FF D0 E8 ?? ?? 00 00 CC CC CC CC CC CC CC }

condition:
		$a0
}
	
	
rule VxIgor
{
strings:
		$a0 = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C }

condition:
		$a0 at entrypoint
}
	
	
rule FACRYPTv10
{
strings:
		$a0 = { B9 ?? ?? B3 ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01WATCOMCCEXEAnorganix
{
strings:
		$a0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule EmbedPEv113cyclotron
{
strings:
		$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 }

condition:
		$a0 at entrypoint
}
	
	
rule Petite14
{
strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

condition:
		$a0
}
	
	
rule Petite12
{
strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakePESHiELD025emadiciush
{
strings:
		$a0 = { 60 E8 2B 00 00 00 0D 0A 0D 0A 0D 0A 52 65 67 69 73 74 41 72 65 64 20 74 6F 3A 20 4E 4F 4E 2D 43 4F 4D 4D 45 52 43 49 41 4C 21 21 0D 0A 0D 0A 0D 00 58 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule yzpackV20UsAr
{
strings:
		$a0 = { 25 ?? ?? ?? ?? 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3C AA EB DC FF 54 24 04 2B CB 75 0F FF 54 24 08 EB 27 AC D1 E8 74 30 13 C9 EB 1B 91 48 C1 E0 }

condition:
		$a0 at entrypoint
}
	
	
rule GameGuardv20065xxdll
{
strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 BA 4C 00 00 00 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02REALBasic
{
strings:
		$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack021betaDwing
{
strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin10Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

condition:
		$a0
}
	
	
rule ExeShield27b
{
strings:
		$a0 = { EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40 }

condition:
		$a0
}
	
	
rule UPXV200V290MarkusOberhumerampLaszloMolnarampJohnReiser
{
strings:
		$a0 = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

condition:
		$a0
}
	
	
rule ThemidaOreansTechnologies2004
{
strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule VxNumberOne
{
strings:
		$a0 = { F9 07 3C 53 6D 69 6C 65 3E E8 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv085f
{
strings:
		$a0 = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }

condition:
		$a0 at entrypoint
}
	
	
rule EXEShield05Smoke
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 }

condition:
		$a0
}
	
	
rule FreeJoinerSmallbuild014020GlOFF
{
strings:
		$a0 = { E8 ?? ?? FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv50v60MFC
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }

condition:
		$a0 at entrypoint
}
	
	
rule PROTECTEXECOMv50
{
strings:
		$a0 = { 1E 0E 0E 1F 07 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium13021ObsidiumSoftware
{
strings:
		$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 26 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall25h
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D A7 1A 00 00 B9 6C 1A 00 00 BA 20 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD EC 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtectorPro112
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphiv50KOL
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtect14xRISCOsoft
{
strings:
		$a0 = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 }
	$a1 = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 6F 72 74 5F 45 6E 64 73 73 00 }

condition:
		$a0 or $a1
}
	
	
rule SplashBitmapv100BoBBobsoft
{
strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 6A 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PROPACKv208emphasisonpackedsizelocked
{
strings:
		$a0 = { 83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B }

condition:
		$a0 at entrypoint
}
	
	
rule WATCOMCC32RunTimeSystem19881994
{
strings:
		$a0 = { FB 83 ?? ?? 89 E3 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 29 C0 B4 30 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule PEZipv10byBaGIE
{
strings:
		$a0 = { D9 D0 F8 74 02 23 DB F5 F5 50 51 52 53 8D 44 24 10 50 55 56 57 D9 D0 22 C9 C1 F7 A0 55 66 C1 C8 B0 5D 81 E6 FF FF FF FF F8 77 07 52 76 03 72 01 90 5A C1 E0 60 90 BD 1F 01 00 00 87 E8 E2 07 E3 05 17 5D 47 E4 42 41 7F 06 50 66 83 EE 00 58 25 FF FF FF FF 51 0F B6 C9 66 83 F6 00 3D CB 60 47 92 50 40 58 FC E2 EE 59 F8 7C 08 53 74 04 78 02 84 C9 5B 66 0B ED F8 F5 BA 9F FA FF FF 52 57 77 04 78 02 84 E4 5F 5A 50 80 EF 00 58 50 81 E0 FF FF FF FF 58 3C EF FC 7A 05 3D DF DA AC D1 05 00 00 00 00 73 05 71 03 7E 01 90 EB 02 EB 05 E8 F9 FF FF FF 83 C0 00 7B 06 53 66 BB 74 EF 5B F8 8B 3C 24 83 C4 04 51 0F B6 C9 66 C1 C7 30 0B D2 53 66 83 FD F6 5B 55 6A 97 83 C4 04 5D E2 E8 59 53 55 51 66 83 E9 00 59 5D 5B F8 01 FA 22 C9 7A 02 8D 3F 79 08 71 06 52 66 A9 6E E3 5A 51 0F B6 }

condition:
		$a0
}
	
	
rule LamerStopv10ccStefanEsser
{
strings:
		$a0 = { E8 ?? ?? 05 ?? ?? CD 21 33 C0 8E C0 26 ?? ?? ?? 2E ?? ?? ?? 26 ?? ?? ?? 2E ?? ?? ?? BA ?? ?? FA }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtectV14Xrisco
{
strings:
		$a0 = { 60 E8 01 00 00 00 7C 83 04 24 06 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphiv20
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtectorv1033exescrcomAshkbizDanehkarh
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 4B 0C 41 00 81 E9 01 E3 40 00 8B D5 81 C2 01 E3 40 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 9C 22 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 CC CC CC CC AC }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystem1xx
{
strings:
		$a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
	$a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule InstallStub32bit
{
strings:
		$a0 = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29 }

condition:
		$a0 at entrypoint
}
	
	
rule VcasmProtector10evcasm
{
strings:
		$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1200ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 3F 1E 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule BGIStrokedFontv11
{
strings:
		$a0 = { 50 4B 08 08 42 47 49 20 53 74 72 6F 6B 65 64 20 46 6F 6E 74 20 56 31 2E 31 }

condition:
		$a0
}
	
	
rule Armadillov190b2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov190b3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv022v023BetaSignbyhot_UNP
{
strings:
		$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov190b4
{
strings:
		$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 B4 96 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02BJFNT12
{
strings:
		$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv103v104Modified
{
strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov430440SiliconRealmsToolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? 00 68 80 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 ?? ?? 00 33 D2 8A D4 89 15 30 ?? ?? 00 8B C8 81 E1 FF 00 00 00 89 0D 2C ?? ?? 00 C1 E1 08 03 CA 89 0D 28 ?? ?? 00 C1 E8 10 A3 24 ?? ?? 00 33 F6 56 E8 78 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 43 13 00 00 FF 15 8C ?? ?? 00 A3 24 }
	$a1 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 }

condition:
		$a0 or $a1
}
	
	
rule BamBam001
{
strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? 00 A1 2B ?? ?? 00 66 8B 15 2F ?? ?? 00 B9 80 ?? ?? 00 2B CF 89 45 E8 89 0D 6B ?? ?? 00 66 89 55 EC 8B 41 3C 33 D2 03 C1 }

condition:
		$a0
}
	
	
rule RLPackV118DllaPlib043ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 5C 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 }

condition:
		$a0 at entrypoint
}
	
	
rule PACKWINv101p
{
strings:
		$a0 = { 8C C0 FA 8E D0 BC ?? ?? FB 06 0E 1F 2E ?? ?? ?? ?? 8B F1 4E 8B FE 8C DB 2E ?? ?? ?? ?? 8E C3 FD F3 A4 53 B8 ?? ?? 50 CB }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakePEX099emadiciush
{
strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv110b1
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }

condition:
		$a0 at entrypoint
}
	
	
rule MicroJoiner15coban2k
{
strings:
		$a0 = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv110b3
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv110b2
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv110b5
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }

condition:
		$a0 at entrypoint
}
	
	
rule NJoy10NEX
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 9C 3B 40 00 E8 8C FC FF FF 6A 00 68 E4 39 40 00 6A 0A 6A 00 E8 40 FD FF FF E8 EF F5 FF FF 8D 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv110b7
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv110b6
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7 }

condition:
		$a0 at entrypoint
}
	
	
rule MASMTASM
{
strings:
		$a0 = { 6A 00 E8 ?? 0? 00 00 A3 ?? 32 40 00 E8 ?? 0? 00 00 }
	$a1 = { 6A 00 E8 ?? 0? 00 00 A3 ?? ?? 40 00 ?? ?? ?? ?0 ?0 ?? ?? 00 00 00 ?? ?? 0? ?? ?? ?0 ?? ?? ?0 ?0 ?? ?? ?? ?0 ?? 0? ?? ?0 ?0 00 }
	$a2 = { 6A 00 E8 ?? ?? 00 00 A3 ?? 32 40 00 E8 ?? ?? 00 00 }

condition:
		$a0 at entrypoint or $a1 or $a2
}
	
	
rule KBysPacker028BetaShoooo
{
strings:
		$a0 = { 60 E8 00 00 00 00 5E 83 EE 0A 8B 06 03 C2 8B 08 89 4E F3 83 EE 0F 56 52 8B F0 AD AD 03 C2 8B D8 6A 04 BF 00 10 00 00 57 57 6A 00 FF 53 08 5A 59 BD 00 80 00 00 55 6A 00 50 51 52 50 89 06 AD AD 03 C2 50 AD 03 C2 FF D0 6A 04 57 AD 50 6A 00 FF 53 }

condition:
		$a0
}
	
	
rule nPack113002006BetaNEOx
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 2D 02 00 00 E8 DD 06 00 00 E8 2C 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv0896v102v105v122Modified
{
strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 }

condition:
		$a0 at entrypoint
}
	
	
rule FileAnalyzerCompiledDatafileVersion
{
strings:
		$a0 = { 46 69 6C 65 20 41 6E 61 6C 79 7A 65 72 20 43 6F 6D 70 69 6C 65 64 20 44 61 74 61 66 69 6C 65 20 56 65 72 73 69 6F 6E }

condition:
		$a0
}
	
	
rule PseudoSigner02BorlandC1999Anorganix
{
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv092a
{
strings:
		$a0 = { E9 7E E9 FF FF 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SEAAXEv22
{
strings:
		$a0 = { FC BC ?? ?? 0E 1F A3 ?? ?? E8 ?? ?? A1 ?? ?? 8B ?? ?? ?? 2B C3 8E C0 B1 03 D3 E3 8B CB BF ?? ?? 8B F7 F3 A5 }

condition:
		$a0 at entrypoint
}
	
	
rule PureBasic4xDLLNeilHodgson
{
strings:
		$a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

condition:
		$a0 at entrypoint
}
	
	
rule EXEPackerv70byTurboPowerSoftware
{
strings:
		$a0 = { 1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE }

condition:
		$a0 at entrypoint
}
	
	
rule VxSYP
{
strings:
		$a0 = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A }

condition:
		$a0 at entrypoint
}
	
	
rule DSHIELD
{
strings:
		$a0 = { 06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E }

condition:
		$a0 at entrypoint
}
	
	
rule kkrunchy023alphaRyd
{
strings:
		$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 ?? 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 ?? 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 ?? 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 ?? 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE ?? ?? ?? 00 BB ?? ?? ?? 00 55 46 AD 85 C0 74 ?? 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 ?? 56 55 FF 53 04 AB 85 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXInliner10byGPcH
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 }

condition:
		$a0
}
	
	
rule AntiDote12DemoSISTeam
{
strings:
		$a0 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Packv137
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40 }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Packv136
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40 }

condition:
		$a0 at entrypoint
}
	
	
rule AINEXEv230
{
strings:
		$a0 = { 0E 07 B9 ?? ?? BE ?? ?? 33 FF FC F3 A4 A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtector10bAshkbizDanehkar
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 }

condition:
		$a0
}
	
	
rule EXECryptorv151x
{
strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

condition:
		$a0 at entrypoint
}
	
	
rule CopyProtectorv20
{
strings:
		$a0 = { 2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F }

condition:
		$a0 at entrypoint
}
	
	
rule NetopsystemsFEADOptimizer
{
strings:
		$a0 = { 60 BE 00 50 43 00 8D BE 00 C0 FC FF }
	$a1 = { E8 00 00 00 00 58 BB 00 00 40 00 8B }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule EXE32Packv138
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D 40 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtBorlandC1999
{
strings:
		$a0 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }

condition:
		$a0 at entrypoint
}
	
	
rule KbysPacker028Betashoooo314
{
strings:
		$a0 = { 68 85 AE 01 01 E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 }

condition:
		$a0
}
	
	
rule FSGv131Engdulekxt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 97 33 C9 41 FF D3 13 C9 FF D3 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 5B 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 58 FF FF FF 5F BB ?? ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 89 06 AD 85 C0 75 D9 8B EC C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 88 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtectorBasicProEdition110RandyLi
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 }

condition:
		$a0 at entrypoint
}
	
	
rule Petite12c1998IanLuck
{
strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0D 00 0F 00 11 00 13 00 17 00 1B 00 1F 00 23 00 2B 00 33 00 3B 00 43 00 53 00 63 00 73 00 83 00 A3 00 C3 00 E3 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 02 02 02 }

condition:
		$a0 at entrypoint
}
	
	
rule PcSharev40
{
strings:
		$a0 = { 55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1 }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector0X12Xvcasm
{
strings:
		$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }

condition:
		$a0
}
	
	
rule PKLITE32v11
{
strings:
		$a0 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 00 00 00 5D C2 0C 00 8B 45 0C 57 56 53 8B 5D 10 }
	$a1 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10 }
	$a2 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8 }
	$a3 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 44 24 0C 50 }

condition:
		$a0 at entrypoint or $a1 or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule WiseInstallerStub11010291
{
strings:
		$a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 }

condition:
		$a0
}
	
	
rule SCRAMvC5
{
strings:
		$a0 = { B8 ?? ?? 50 9D 9C 58 25 ?? ?? 75 ?? BA ?? ?? B4 09 CD 21 CD 20 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack116LZMAcompressionap0xh
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 EB 09 00 00 89 85 3A 0A 00 00 EB 14 60 FF B5 3A 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 08 83 3C 37 00 75 E6 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 56 0A 00 00 5B 60 FF B5 3A 0A 00 00 56 FF B5 56 0A 00 00 FF D3 61 8B B5 56 0A 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 E8 E7 00 00 00 83 C0 04 89 85 52 0A 00 00 E9 97 00 00 00 56 FF 95 E3 09 00 00 89 85 4E 0A 00 00 85 C0 0F 84 C2 }

condition:
		$a0
}
	
	
rule PseudoSigner02WATCOMCCEXE
{
strings:
		$a0 = { E9 00 00 00 00 90 90 90 90 57 41 }

condition:
		$a0 at entrypoint
}
	
	
rule STNPEE113
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxTrojanTelefoon
{
strings:
		$a0 = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidiumv10061
{
strings:
		$a0 = { E8 AF 1C 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule FreePascalv1010win32console
{
strings:
		$a0 = { C6 05 ?? ?? ?? 00 01 E8 ?? ?? 00 00 C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 ?? EC }

condition:
		$a0
}
	
	
rule WinKriptv10MrCrimsonh
{
strings:
		$a0 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 83 C0 08 EB D5 61 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtector101AshkbizDanehkarh
{
strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 }

condition:
		$a0
}
	
	
rule CDCopsII
{
strings:
		$a0 = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack11BasicEditionap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Packv13x
{
strings:
		$a0 = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? E8 ?? ?? ?? ?? 3B 74 01 ?? 5D 8B D5 81 ED }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02VOBProtectCD5
{
strings:
		$a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule WinZip32bit6x
{
strings:
		$a0 = { FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacKV36LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule nPack112502006BetaNEOxuinC
{
strings:
		$a0 = { 83 3D 04 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E ?? ?? ?? 2B 05 08 ?? ?? ?? A3 00 ?? ?? ?? E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 ?? ?? ?? C7 05 04 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 }

condition:
		$a0
}
	
	
rule EXECrypt10ReBirth
{
strings:
		$a0 = { 90 90 60 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 4E 28 40 00 8B F7 AC }

condition:
		$a0 at entrypoint
}
	
	
rule NJoy11NEX
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 0C 3C 40 00 E8 24 FC FF FF 6A 00 68 28 3A 40 00 6A 0A 6A 00 E8 D8 FC FF FF E8 7F F5 FF FF 8D 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule CrackStopv101cStefanEsser1997
{
strings:
		$a0 = { B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC }

condition:
		$a0 at entrypoint
}
	
	
rule CrunchPEv30xx
{
strings:
		$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74 }

condition:
		$a0 at entrypoint
}
	
	
rule LameCryptLaZaRus
{
strings:
		$a0 = { 60 66 9C BB 00 ?? ?? 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 ?? ?? 40 00 FF E0 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack29NorthStar
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8A 06 3C 00 74 12 8B F5 8D B5 ?? ?? FF FF 8A 06 3C 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }

condition:
		$a0 at entrypoint
}
	
	
rule KBySV028DLLshooooSignbyfly
{
strings:
		$a0 = { B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 03 C2 FF E0 ?? ?? ?? ?? 60 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PEShit
{
strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF }

condition:
		$a0 at entrypoint
}
	
	
rule TurboPascalv301985
{
strings:
		$a0 = { 90 90 CD AB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 35 }

condition:
		$a0 at entrypoint
}
	
	
rule MinkeV101CodiusSignbyfly
{
strings:
		$a0 = { 26 3D 4F 38 C2 82 37 B8 F3 24 42 03 17 9B 3A 83 01 00 00 CC 00 00 00 00 06 00 00 00 01 64 53 74 75 62 00 10 55 54 79 70 65 73 00 00 C7 53 79 73 74 65 6D 00 00 81 53 79 73 49 6E 69 74 00 0C 4B 57 69 6E 64 6F 77 73 00 00 8A 75 46 75 6E 63 74 69 6F 6E 73 }

condition:
		$a0
}
	
	
rule FSGv110EngdulekxtBorlandC
{
strings:
		$a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
	$a1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA 33 0F B6 C9 0F BE 0E 88 16 EB 01 5F EB 01 6B 46 EB 01 6D 0F BE C0 4B EB 02 CD 20 0F BE C9 2B C9 3B D9 75 B0 EB 01 99 C1 C1 05 91 9D B2 E3 22 E2 A1 E2 F2 22 E2 A0 ?? ?? ?? E2 35 CA EC E2 E2 E2 E4 B4 57 E7 6C F8 28 F4 B4 A5 94 62 15 BD 86 95 E4 E1 F6 06 55 DA 15 AB E1 F6 06 55 FA 15 A2 E1 F6 06 55 03 95 E4 23 92 F2 E1 F6 06 F4 A2 55 DB 57 21 8C CD BE CA 25 E2 E2 E2 0D AD 57 F2 CA 1A E2 E2 E2 CD 0A 8E B3 CA 56 23 F5 AB CD FE 73 2A A3 C2 EA 8E CA 04 E2 E2 E2 1F E2 5F E2 E2 55 EC 62 DE E7 55 E8 65 DA 61 59 E4 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RLPackFullEdition117iBoxaPLib
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 79 29 00 00 8D 9D 2C 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 }

condition:
		$a0 at entrypoint
}
	
	
rule ZortechCv30
{
strings:
		$a0 = { FA FC B8 ?? ?? ?? 8C C8 8E D8 }

condition:
		$a0 at entrypoint
}
	
	
rule VIRUSIWormKLEZ
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0 }

condition:
		$a0
}
	
	
rule UPXv060v061
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE3211
{
strings:
		$a0 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv20bartxt
{
strings:
		$a0 = { 87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMASM32TASM32MicrosoftVisualBasic
{
strings:
		$a0 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor239DLLminimumprotection
{
strings:
		$a0 = { 51 68 ?? ?? ?? ?? 87 2C 24 8B CD 5D 81 E1 ?? ?? ?? ?? E9 ?? ?? ?? 00 89 45 F8 51 68 ?? ?? ?? ?? 59 81 F1 ?? ?? ?? ?? 0B 0D ?? ?? ?? ?? 81 E9 ?? ?? ?? ?? E9 ?? ?? ?? 00 81 C2 ?? ?? ?? ?? E8 ?? ?? ?? 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C E9 ?? ?? ?? 00 F7 D6 2B D5 E9 ?? ?? ?? 00 87 3C 24 8B CF 5F 87 14 24 1B CA E9 ?? ?? ?? 00 83 C4 08 68 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? 00 E9 ?? ?? ?? 00 50 8B C5 87 04 24 8B EC 51 0F 88 ?? ?? ?? 00 FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 99 03 04 24 E9 ?? ?? ?? 00 C3 81 D5 ?? ?? ?? ?? 9C E9 ?? ?? ?? 00 81 FA ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 15 81 CB ?? ?? ?? ?? 81 F3 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 87 }

condition:
		$a0 at entrypoint
}
	
	
rule Frusionbiff
{
strings:
		$a0 = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV20XJititSignbyfly
{
strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo410SiliconRealmsToolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 D0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 7C A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 78 A5 4C 00 C1 E1 08 03 CA 89 0D 74 A5 4C 00 C1 E8 10 A3 70 A5 }

condition:
		$a0
}
	
	
rule OpenSourceCodeCrypterp0ke
{
strings:
		$a0 = { 55 8B EC B9 09 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 34 44 40 00 E8 28 F8 FF FF 33 C0 55 68 9F 47 40 00 64 FF 30 64 89 20 BA B0 47 40 00 B8 1C 67 40 00 E8 07 FD FF FF 8B D8 85 DB 75 07 6A 00 E8 C2 F8 FF FF BA 28 67 40 00 8B C3 8B 0D 1C 67 40 00 E8 F0 }
	$a1 = { 55 8B EC B9 09 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 34 44 40 00 E8 28 F8 FF FF 33 C0 55 68 9F 47 40 00 64 FF 30 64 89 20 BA B0 47 40 00 B8 1C 67 40 00 E8 07 FD FF FF 8B D8 85 DB 75 07 6A 00 E8 C2 F8 FF FF BA 28 67 40 00 8B C3 8B 0D 1C 67 40 00 E8 F0 E0 FF FF BE 01 00 00 00 B8 2C 68 40 00 E8 E1 F0 FF FF BF 0A 00 00 00 8D 55 EC 8B C6 E8 92 FC FF FF 8B 4D EC B8 2C 68 40 00 BA BC 47 40 00 E8 54 F2 FF FF A1 2C 68 40 00 E8 52 F3 FF FF 8B D0 B8 20 67 40 00 E8 A2 FC FF FF 8B D8 85 DB 0F 84 52 02 00 00 B8 24 67 40 00 8B 15 20 67 40 00 E8 78 F4 FF FF B8 24 67 40 00 E8 7A F3 FF FF 8B D0 8B C3 8B 0D 20 67 40 00 E8 77 E0 FF FF 8D 55 E8 A1 24 67 40 00 E8 42 FD FF FF 8B 55 E8 B8 24 67 40 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule BorlandCBorlandBuilder
{
strings:
		$a0 = { 3B CF 76 05 2B CF FC F3 AA 59 }

condition:
		$a0
}
	
	
rule ASPackv21
{
strings:
		$a0 = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SoftwareCompressv14LITEBGSoftwareProtectTechnologiesh
{
strings:
		$a0 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A }
	$a1 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A 41 00 8B 4A 64 89 8D 51 1A 41 00 8B 4A 74 89 8D 59 1A 41 00 68 00 20 00 00 E8 D2 00 00 00 50 8D 8D 00 1C 41 00 50 51 E8 1B 00 00 00 83 C4 08 58 8D 78 74 8D B5 49 1A 41 00 B9 18 00 00 00 F3 A4 05 A4 00 00 00 50 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 4D 1A 41 00 89 44 24 1C 61 C2 04 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule SVKProtectorv1051
{
strings:
		$a0 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }

condition:
		$a0 at entrypoint
}
	
	
rule MSFORTRANLibrary19
{
strings:
		$a0 = { FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC 8C DB 8E C3 BB ?? ?? 9A ?? ?? ?? ?? 9B DB E3 9B D9 2E ?? ?? 33 C9 }
	$a1 = { FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC B8 ?? ?? 8E C0 26 C7 ?? ?? ?? ?? ?? 26 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule TheHypersprotectorTheHyperh
{
strings:
		$a0 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 ?? ?? 01 01 ?? ?? 01 01 ?? ?? ?? 00 ?? ?? 01 01 ?? ?? 02 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8 }
	$a1 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 ?? ?? 01 01 ?? ?? 01 01 ?? ?? ?? 00 ?? ?? 01 01 ?? ?? 02 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8 0C 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 53 8B 06 FF 10 89 47 04 E8 0F 00 00 00 47 65 74 50 72 6F 63 65 73 73 48 65 61 70 00 53 8B 06 FF 10 89 47 08 E8 0A 00 00 00 48 65 61 70 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 47 0C E8 09 00 00 00 48 65 61 70 46 72 65 65 00 53 8B 06 FF 10 89 47 10 57 FF 76 08 FF 76 0C FF 56 10 8B E5 5D }
	$a2 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 ?? ?? 01 01 ?? ?? 01 01 ?? ?? ?? 00 ?? ?? 01 01 ?? ?? ?? 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8 0C 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 53 8B 06 FF 10 89 47 04 E8 0F 00 00 00 47 65 74 50 72 6F 63 65 73 73 48 65 61 70 00 53 8B 06 FF 10 89 47 08 E8 0A 00 00 00 48 65 61 70 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 47 0C E8 09 00 00 00 48 65 61 70 46 72 65 65 00 53 8B 06 FF 10 89 47 10 57 FF 76 08 FF 76 0C FF 56 10 8B E5 5D }

condition:
		$a0 or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule PEPacker
{
strings:
		$a0 = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }

condition:
		$a0 at entrypoint
}
	
	
rule ProgramProtectorXPv10
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePack111Method2NTbagieTMX
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01BorlandDelphi6070
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032aemadicius
{
strings:
		$a0 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 }

condition:
		$a0
}
	
	
rule kkrunchyV02XRydSignbyfly
{
strings:
		$a0 = { BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? ?? 57 BE ?? ?? ?? ?? 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv106b
{
strings:
		$a0 = { 90 90 90 75 00 E9 }
	$a1 = { 90 90 75 00 E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ThinstallEmbeddedV19XJititSignbyfly
{
strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin01Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

condition:
		$a0
}
	
	
rule NativeUDPacker11ModdedPoisonIvyShellcodeokkixot
{
strings:
		$a0 = { 31 C0 31 DB 31 C9 EB 0E 6A 00 6A 00 6A 00 6A 00 FF 15 28 41 40 00 FF 15 94 40 40 00 89 C7 68 88 13 00 00 FF 15 98 40 40 00 FF 15 94 40 40 00 81 C7 88 13 00 00 39 F8 73 05 E9 84 00 00 00 6A 40 68 00 10 00 00 FF 35 04 30 40 00 6A 00 FF 15 A4 40 40 00 89 C7 FF 35 04 30 40 00 68 CA 10 40 00 50 FF 15 A8 40 40 00 6A 40 68 00 10 00 00 FF 35 08 30 40 00 6A 00 FF 15 A4 40 40 00 89 C6 68 00 30 40 00 FF 35 04 30 40 00 57 FF 35 08 30 40 00 50 6A 02 FF 15 4E 41 40 00 6A 00 6A 00 6A 00 56 6A 00 6A 00 FF 15 9C 40 40 00 50 6A 00 6A 00 6A 11 50 FF 15 4A 41 40 00 58 6A FF 50 FF 15 AC 40 40 00 6A 00 FF 15 A0 40 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidiumv1304ObsidiumSoftwareh
{
strings:
		$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule NXPEPackerv10
{
strings:
		$a0 = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Safeguard10Simonzh
{
strings:
		$a0 = { E8 00 00 00 00 EB 29 }

condition:
		$a0 at entrypoint
}
	
	
rule PolyBoxCAnskya
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 E4 41 00 10 E8 3A E1 FF FF 33 C0 55 68 11 44 00 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 6A 0A 68 20 44 00 10 A1 1C 71 00 10 50 E8 CC E1 ?? ?? ?? ?? 85 DB 0F 84 77 01 00 00 53 A1 1C 71 00 10 50 E8 1E E2 FF FF 8B F0 85 F6 0F 84 61 01 00 00 53 A1 1C 71 00 10 50 E8 E0 E1 FF FF 85 C0 0F 84 4D 01 00 00 50 E8 DA E1 FF FF 8B D8 85 DB 0F 84 3D 01 00 00 56 B8 70 80 00 10 B9 01 00 00 00 8B 15 98 41 00 10 E8 9E DE FF FF 83 C4 04 A1 70 80 00 10 8B CE 8B D3 E8 E1 E1 FF FF 6A 00 6A 00 A1 70 80 00 10 B9 30 44 00 10 8B D6 E8 F8 FD FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinv10Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 D2 42 40 00 8B 42 3C 03 C2 89 85 DC 42 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D F0 42 40 00 53 8F 85 94 41 40 00 BB ?? 00 00 00 B9 8C 0B 00 00 8D BD 80 43 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 40 4E 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 FD 68 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SLVc0deProtector11SLVh
{
strings:
		$a0 = { E8 01 00 00 00 A0 5D EB 01 69 81 ED 5F 1A 40 00 8D 85 92 1A 40 00 F3 8D 95 83 1A 40 00 8B C0 8B D2 2B C2 83 E8 05 89 42 01 E8 FB FF FF FF 69 83 C4 08 E8 06 00 00 00 69 E8 F2 FF FF FF F3 B9 05 00 00 00 51 8D B5 BF 1A 40 00 8B FE B9 58 15 00 00 AC 32 C1 F6 }

condition:
		$a0
}
	
	
rule Berio100betah
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 01 12 00 00 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 B0 01 00 83 BD 22 04 00 00 00 89 9D 22 04 00 00 0F 85 65 03 00 00 8D 85 2E 04 00 00 50 FF 95 4D 0F }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCDLL
{
strings:
		$a0 = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00 }
	$a1 = { 53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14 }
	$a2 = { 53 B8 01 00 00 00 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0 }
	$a3 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule beriav007publicWIPsymbiont
{
strings:
		$a0 = { 83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0 }

condition:
		$a0 at entrypoint
}
	
	
rule EmbedPEV100V124cyclotronSignbyfly
{
strings:
		$a0 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule asscrypterbysantasdad
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 98 40 00 10 E8 AC EA FF FF 33 C0 55 68 78 51 00 10 64 ?? ?? ?? ?? 20 6A 0A 68 88 51 00 10 A1 E0 97 00 10 50 E8 D8 EA FF FF 8B D8 53 A1 E0 97 00 10 50 E8 12 EB FF FF 8B F8 53 A1 E0 97 00 10 50 E8 DC EA FF FF 8B }
	$a1 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 98 40 00 10 E8 AC EA FF FF 33 C0 55 68 78 51 00 10 64 ?? ?? ?? ?? 20 6A 0A 68 88 51 00 10 A1 E0 97 00 10 50 E8 D8 EA FF FF 8B D8 53 A1 E0 97 00 10 50 E8 12 EB FF FF 8B F8 53 A1 E0 97 00 10 50 E8 DC EA FF FF 8B D8 53 E8 DC EA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 F0 97 00 10 E8 C9 E7 FF FF B8 F0 97 00 10 E8 B7 E7 FF FF 8B CF 8B D6 E8 EE EA FF FF 53 E8 98 EA FF FF 8D 4D EC BA 9C 51 00 10 A1 F0 97 00 10 E8 22 EB FF FF 8B 55 EC B8 F0 97 00 10 E8 89 E6 FF FF B8 F0 97 00 10 E8 7F E7 FF FF E8 6E EC FF FF 33 C0 5A 59 59 64 89 10 68 7F 51 00 10 8D 45 EC E8 11 E6 FF FF C3 E9 FF DF FF FF EB F0 5F 5E 5B E8 0D E5 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 1C 00 00 00 45 4E 54 45 52 20 59 4F 55 52 20 4F 57 4E 20 50 41 53 53 57 4F 52 44 20 48 45 52 45 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule FSGv110Engbartxt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB 27 ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 07 74 EF FE 07 75 06 47 FF 37 AF EB 09 FE 07 0F 84 1A ?? ?? FF 57 55 FF 53 04 09 06 AD 75 DB 8B EC C3 1B ?? ?? 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV115V117Dllap0xSignbyfly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }

condition:
		$a0 at entrypoint
}
	
	
rule Elanguage
{
strings:
		$a0 = { E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule EXELOCK66615
{
strings:
		$a0 = { BA ?? ?? BF ?? ?? EB ?? EA ?? ?? ?? ?? 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9 }

condition:
		$a0 at entrypoint
}
	
	
rule AdysGluev010
{
strings:
		$a0 = { 2E 8C 06 ?? ?? 0E 07 33 C0 8E D8 BE ?? ?? BF ?? ?? FC B9 ?? ?? 56 F3 A5 1E 07 5F }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV2312JititSignbyfly
{
strings:
		$a0 = { 6A 00 FF 15 ?? ?? ?? ?? E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SVKProtectorv132
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITEv114v115v1203
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B ?? ?? ?? 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F }

condition:
		$a0 at entrypoint
}
	
	
rule WARNINGTROJANRobinPE
{
strings:
		$a0 = { 60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PCGuardforWin32500SofProBlagojeCeklich
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 ?? ?? ?? 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }

condition:
		$a0
}
	
	
rule AmigaIFFILBMGraphicsformat
{
strings:
		$a0 = { 46 4F 52 4D ?? ?? ?? ?? 49 4C 42 4D 42 4D 48 44 }

condition:
		$a0
}
	
	
rule CCv261Beta
{
strings:
		$a0 = { BA ?? ?? B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoinerSmallbuild023GlOFF
{
strings:
		$a0 = { E8 E1 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MinGWv32xDll_WinMain
{
strings:
		$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 A4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 1B 02 00 00 E8 A6 01 00 00 E9 75 FF FF FF E8 6C 05 00 00 C7 00 0C 00 00 00 31 C0 EB 98 89 F6 55 89 E5 83 EC 08 89 5D FC 8B 15 00 30 00 10 85 D2 74 29 8B 1D 10 30 00 10 83 EB 04 39 D3 72 0D 8B 03 85 C0 75 2A 83 EB 04 39 D3 73 F3 89 14 24 E8 1B 05 00 00 31 C0 A3 00 30 00 10 C7 04 24 00 00 00 00 E8 F8 04 00 00 8B 5D FC 89 EC 5D C3 }

condition:
		$a0 at entrypoint
}
	
	
rule WATCOMCC32RunTimeSystem19891994
{
strings:
		$a0 = { 0E 1F 8C C6 B4 ?? 50 BB ?? ?? CD 21 73 ?? 58 CD 21 72 }

condition:
		$a0 at entrypoint
}
	
	
rule PrivatePersonalPackerPPP102ConquestOfTroycom
{
strings:
		$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 }
	$a1 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PESpinv03Engcyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 }
	$a1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule DIETv102bv110av120
{
strings:
		$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallVirtualizationSuiteV30XThinstallCompanySignbyfly
{
strings:
		$a0 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA ?? ?? ?? ?? 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 ?? ?? ?? ?? E8 DF 00 00 00 73 1B 55 BD ?? ?? ?? ?? E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1334ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact2xBitsumTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? 02 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

condition:
		$a0
}
	
	
rule FSG120EngdulekxtMicrosoftVisualC6070
{
strings:
		$a0 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }

condition:
		$a0
}
	
	
rule PrivateEXEProtector18SetiSofth
{
strings:
		$a0 = { A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 FF 31 F6 C3 }

condition:
		$a0
}
	
	
rule PKLITEv150Devicedrivercompression
{
strings:
		$a0 = { B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB }

condition:
		$a0 at entrypoint
}
	
	
rule VxGrazie883
{
strings:
		$a0 = { 1E 0E 1F 50 06 BF 70 03 B4 1A BA 70 03 CD 21 B4 47 B2 00 BE 32 04 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule PROTECTEXECOMv60
{
strings:
		$a0 = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor120b
{
strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? 00 2B 05 84 ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 16 A1 ?? ?? ?? 00 03 05 80 ?? ?? 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 68 04 }

condition:
		$a0
}
	
	
rule PECompactv147v150
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01Neolite20
{
strings:
		$a0 = { E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule PocketPCMIB
{
strings:
		$a0 = { E8 FF BD 27 14 00 BF AF 18 00 A4 AF 1C 00 A5 AF 20 00 A6 AF 24 00 A7 AF ?? ?? ?? 0C 00 00 00 00 18 00 A4 8F 1C 00 A5 8F 20 00 A6 8F ?? ?? ?? 0C 24 00 A7 8F ?? ?? ?? 0C 25 20 40 00 14 00 BF 8F 08 00 E0 03 18 00 BD 27 ?? FF BD 27 18 00 ?? AF }
	$a1 = { E8 FF BD 27 14 00 BF AF 18 00 A4 AF 1C 00 A5 AF 20 00 A6 AF 24 00 A7 AF ?? ?? ?? 0C 00 00 00 00 18 00 A4 8F 1C 00 A5 8F 20 00 A6 8F ?? ?? ?? 0C 24 00 A7 8F ?? ?? ?? 0C 25 20 40 00 14 00 BF 8F 08 00 E0 03 18 00 BD 27 ?? FF BD 27 18 00 ?? AF ?? 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule WWPACKv305c4ExtractableVirusShield
{
strings:
		$a0 = { 03 05 40 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule FSG110Engbartxt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxNoon1163
{
strings:
		$a0 = { E8 ?? ?? 5B 50 56 B4 CB CD 21 3C 07 ?? ?? 81 ?? ?? ?? 2E ?? ?? 4D 5A ?? ?? BF 00 01 89 DE FC }

condition:
		$a0 at entrypoint
}
	
	
rule PuNkMoD1xPuNkDuDe
{
strings:
		$a0 = { 94 B9 ?? ?? 00 00 BC ?? ?? ?? ?? 80 34 0C }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_PatchSignbyhot_UNP
{
strings:
		$a0 = { 81 3A 00 00 00 02 00 00 00 00 }
	$a1 = { 2A A3 F2 54 CE }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule PeStubOEPv1x
{
strings:
		$a0 = { 90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF }
	$a1 = { E8 05 00 00 00 33 C0 40 48 C3 E8 05 }

condition:
		$a0 or $a1
}
	
	
rule Unknownpacker08
{
strings:
		$a0 = { 8B C4 2D ?? ?? 24 00 8B F8 57 B9 ?? ?? BE ?? ?? F3 A5 FD C3 97 4F 4F }

condition:
		$a0 at entrypoint
}
	
	
rule InnoSetupModulev2018
{
strings:
		$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 }

condition:
		$a0
}
	
	
rule Unknownpacker07
{
strings:
		$a0 = { 8C C8 05 ?? ?? 50 B8 ?? ?? 50 B0 ?? 06 8C D2 06 83 }

condition:
		$a0 at entrypoint
}
	
	
rule Nakedbind10nakedcrew
{
strings:
		$a0 = { 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacKV31LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 }

condition:
		$a0 at entrypoint
}
	
	
rule AntiVirusVaccinev103
{
strings:
		$a0 = { FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2 }

condition:
		$a0 at entrypoint
}
	
	
rule PEStubOEPv1x
{
strings:
		$a0 = { 40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3 }

condition:
		$a0
}
	
	
rule VxKuku448
{
strings:
		$a0 = { AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectv12xNewStrain
{
strings:
		$a0 = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV115V117aPlib043ap0xSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote10Demo12SISTeam
{
strings:
		$a0 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 65 73 75 6D 65 54 68 72 65 61 64 00 00 29 03 53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 94 03 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 00 6B 03 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 00 00 A6 02 52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 CA 01 47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 62 00 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C }

condition:
		$a0
}
	
	
rule RLPV073betaap0xSignbyfly
{
strings:
		$a0 = { 2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }

condition:
		$a0
}
	
	
rule NoodleCrypt200EngNoodleSpa
{
strings:
		$a0 = { EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02 }

condition:
		$a0
}
	
	
rule FSGv110EngbartxtWinRARSFX
{
strings:
		$a0 = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
	$a1 = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule y0dasCrypterv1xModified
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC }

condition:
		$a0 at entrypoint
}
	
	
rule UPX290LZMA
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
	$a1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
	$a2 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule PseudoSigner02PESHiELD025
{
strings:
		$a0 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorV16dVaskaSignbyfly
{
strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 at entrypoint
}
	
	
rule SetupFactory6003SetupLauncher
{
strings:
		$a0 = { 55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89 }

condition:
		$a0
}
	
	
rule SLVc0deProtector11xSLVICU
{
strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RJoinerbyVaskaSignfrompinch250320071700
{
strings:
		$a0 = { E8 03 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 6C 10 40 00 FF 25 70 10 40 00 FF 25 74 10 40 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2xxcompressedresourceswwwstrongbitcom
{
strings:
		$a0 = { 56 57 53 31 DB 89 C6 89 D7 0F B6 06 89 C2 83 E0 1F C1 EA 05 74 2D 4A 74 15 8D 5C 13 02 46 C1 E0 08 89 FA 0F B6 0E 46 29 CA 4A 29 C2 EB 32 C1 E3 05 8D 5C 03 04 46 89 FA 0F B7 0E 29 CA 4A 83 C6 02 EB 1D C1 E3 04 46 89 C1 83 E1 0F 01 CB C1 E8 05 73 07 43 89 }

condition:
		$a0 at entrypoint
}
	
	
rule AverCryptor10os1r1s
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 BC 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 98 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }

condition:
		$a0 at entrypoint
}
	
	
rule FreeBASICv011
{
strings:
		$a0 = { E8 ?? ?? 00 00 E8 01 00 00 00 C3 55 89 E5 }

condition:
		$a0 at entrypoint
}
	
	
rule PUNiSHERV15FEUERRADER
{
strings:
		$a0 = { 3F 00 00 80 66 20 ?? 00 7E 20 ?? 00 92 20 ?? 00 A4 20 ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 }

condition:
		$a0
}
	
	
	
	
rule UnknownUPXmodifyer
{
strings:
		$a0 = { E8 02 00 00 00 CD 03 5A 81 C2 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 89 D1 81 C1 3C 05 00 00 52 81 2A 33 53 45 12 83 C2 04 39 CA 7E F3 89 CA 8B 42 04 8D 18 29 02 BB 78 56 00 00 83 EA 04 3B 14 24 7D EC C3 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtectorv102exescrcomAshkbizDanehkarh
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 35 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 BE 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }

condition:
		$a0 at entrypoint
}
	
	
rule nSpackV23LiuXingPing
{
strings:
		$a0 = { 9C 60 70 61 63 6B 24 40 }

condition:
		$a0
}
	
	
rule VxVirusConstructorbased
{
strings:
		$a0 = { BB ?? ?? B9 ?? ?? 2E ?? ?? ?? ?? 43 43 ?? ?? 8B EC CC 8B ?? ?? 81 ?? ?? ?? 06 1E B8 ?? ?? CD 21 3D ?? ?? ?? ?? 8C D8 48 8E D8 }
	$a1 = { E8 ?? ?? 5D 81 ?? ?? ?? 06 1E E8 ?? ?? E8 ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B4 4A BB FF FF CD 21 83 ?? ?? B4 4A CD 21 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule SENDebugProtector
{
strings:
		$a0 = { BB ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 29 ?? ?? 4E E8 }

condition:
		$a0 at entrypoint
}
	
	
rule xPEP03xxIkUg
{
strings:
		$a0 = { 55 53 56 51 52 57 E8 16 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorV1451CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D }
	$a1 = { 55 8B EC 83 EC ?? 53 56 57 83 65 ?? 00 F3 EB 0C }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Obsidiumv13037ObsidiumSoftwareh
{
strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB }
	$a1 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule AntiDote14SESISTeam
{
strings:
		$a0 = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 00 6A 00 FF 15 08 10 60 00 68 90 03 00 00 E8 68 FD FF FF 68 69 D6 00 00 E8 5E FD FF FF 50 E8 58 FD FF FF 50 E8 52 FD FF FF E8 DD FE FF FF 50 68 A4 10 60 00 68 94 10 60 00 68 10 22 60 00 E8 58 FD FF FF 83 C4 20 33 C0 C2 10 00 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack30NorthStar
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }

condition:
		$a0 at entrypoint
}
	
	
rule ORiENV212FisunAV
{
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CD 0D }

condition:
		$a0 at entrypoint
}
	
	
rule SentinelSuperProAutomaticProtectionv640Safenet
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 25 FE FF DF 3F 0D 01 00 20 00 A3 ?? ?? ?? ?? 33 C0 50 C7 04 85 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 83 C4 04 83 F8 64 7C ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 A1 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 66 8B 55 00 83 C5 08 }

condition:
		$a0 at entrypoint
}
	
	
rule SplashBitmapv100WithUnpackCodeBoBBobsoft
{
strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40 }

condition:
		$a0 at entrypoint
}
	
	
rule CrackedbyAutoHack1
{
strings:
		$a0 = { FA 50 51 57 56 1E 06 2E 80 3E ?? ?? ?? 74 ?? 8E 06 ?? ?? 2B FF FC }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV12XObsidiumSoftware
{
strings:
		$a0 = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PESPinv13Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 0D 4F 40 00 8B 42 3C 03 C2 89 85 17 4F 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D 2B 4F 40 00 53 8F 85 21 4D 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD D0 4F 40 00 8D 5B 04 8B 1B 89 9D D5 4F 40 00 E8 00 00 00 00 58 01 68 05 68 F7 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC }

condition:
		$a0 at entrypoint
}
	
	
rule GuardantStealthakaNovexDongle
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 60 E8 51 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule AnslymFUDCrypterSignbyfly
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack117
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? 00 00 8D 9D ?? ?? 00 00 33 FF E8 ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 37 FF D3 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01PENinja131Anorganix
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule NorthStarPEShrinker13byLiuxingping
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01 }

condition:
		$a0
}
	
	
rule NTkrnlSecureSuite01015NTkrnlSoftware
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }

condition:
		$a0 at entrypoint
}
	
	
rule PEPROTECT09
{
strings:
		$a0 = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

condition:
		$a0 at entrypoint
}
	
	
rule EXERefactorV01random
{
strings:
		$a0 = { 55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E }

condition:
		$a0 at entrypoint
}
	
	
rule SuckStopv111
{
strings:
		$a0 = { EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftPIMPInstallSystemv1x
{
strings:
		$a0 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PassLock200010EngMoonlightSoftware
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24 }

condition:
		$a0 at entrypoint
}
	
	
rule ThemidaWinLicenseV18XV19XnbspOreansTechnologiesnbspnbspSignByfly
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 05 89 48 01 61 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Pohernah100byKas
{
strings:
		$a0 = { 58 60 E8 00 00 00 00 5D 81 ED 20 25 40 00 8B BD 86 25 40 00 8B 8D 8E 25 40 00 6B C0 05 83 F0 04 89 85 92 25 40 00 83 F9 00 74 2D 81 7F 1C AB 00 00 00 75 1E 8B 77 0C 03 B5 8A 25 40 00 31 C0 3B 47 10 74 0E 50 8B 85 92 25 40 00 30 06 58 40 46 EB ED 83 C7 28 }
	$a1 = { 58 60 E8 00 00 00 00 5D 81 ED 20 25 40 00 8B BD 86 25 40 00 8B 8D 8E 25 40 00 6B C0 05 83 F0 04 89 85 92 25 40 00 83 F9 00 74 2D 81 7F 1C AB 00 00 00 75 1E 8B 77 0C 03 B5 8A 25 40 00 31 C0 3B 47 10 74 0E 50 8B 85 92 25 40 00 30 06 58 40 46 EB ED 83 C7 28 49 EB CE 8B 85 82 25 40 00 89 44 24 1C 61 FF E0 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule UnknownPackerNorthfox
{
strings:
		$a0 = { 54 59 68 61 7A 79 }

condition:
		$a0 at entrypoint
}
	
	
rule dUP2diablo2oo2
{
strings:
		$a0 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 3C 01 75 }
	$a1 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 3C 01 75 19 BE ?? ?? ?? ?? 68 00 02 00 00 56 68 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Petite13c1998IanLuckh
{
strings:
		$a0 = { 9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 72 04 03 7A 08 8B 0A F3 A5 83 C2 0C FC EB D4 8B 7A 08 03 F8 8B 5A 04 85 DB 74 13 52 53 57 03 02 50 E8 7B 00 00 00 85 C0 74 2E 5F 5F 58 5A 8B 4A 0C C1 F9 02 F3 AB 8B 4A 0C 83 E1 03 F3 AA 83 C2 10 EB A0 45 52 52 4F 52 21 00 43 6F 72 72 75 70 74 20 44 61 74 61 21 00 8B 64 24 24 8B 04 24 83 C4 26 8B D0 66 81 C2 6D 01 6A 10 8B D8 66 05 66 01 50 52 6A 00 8B 13 FF 14 1A 6A FF FF 93 ?? ?? 00 00 56 57 8B 7C 24 0C 8B 74 24 10 8B 4C 24 14 C1 F9 02 F3 A5 8B 4C 24 14 83 E1 03 F3 A4 5F 5E C3 }

condition:
		$a0 at entrypoint
}
	
	
rule eXpressorv145CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C }
	$a1 = { 55 8B EC 83 EC ?? 53 56 57 83 65 DC 00 F3 EB 0C }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule hmimysProtectv10
{
strings:
		$a0 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
	$a1 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 00 00 00 }
	$a2 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule Armadillo500DllSiliconRealmsToolworks
{
strings:
		$a0 = { 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 E5 24 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 8F 15 00 00 C7 00 0C 00 00 00 57 57 57 57 57 }

condition:
		$a0 at entrypoint
}
	
	
rule AliasPIXVividIMGGraphicsformat
{
strings:
		$a0 = { 00 00 ?? ?? 00 18 ?? ?? ?? ?? 01 }

condition:
		$a0
}
	
	
rule UPX293LZMA
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01LCCWin32DLLAnorganix
{
strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule CodeCryptv014b
{
strings:
		$a0 = { E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

condition:
		$a0 at entrypoint
}
	
	
rule PellesC450DLLX86CRTLIB
{
strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D ?? ?? ?? ?? 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }

condition:
		$a0
}
	
	
rule SimplePackV10XbagieSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 ?? ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule EEXEVersion112
{
strings:
		$a0 = { B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv120EngdulekxtMASM32TASM32
{
strings:
		$a0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE 58 80 EA 33 C1 E1 12 32 D3 48 80 C2 26 EB 02 CD 20 88 16 F7 D8 46 EB 01 C0 4B 40 8D 0D 00 00 00 00 3B D9 75 B7 EB 01 14 EB 01 0A CF C5 93 53 90 DA 96 67 54 8D CC ?? ?? 51 8E 18 74 53 82 83 80 47 B4 D2 41 FB 64 31 6A AF 7D 89 BC 0A 91 D7 83 37 39 43 50 A2 32 DC 81 32 3A 4B 97 3D D9 63 1F 55 42 F0 45 32 60 9A 28 51 61 4B 38 4B 12 E4 49 C4 99 09 47 F9 42 8C 48 51 4E 70 CF B8 12 2B 78 09 06 07 17 55 D6 EA 10 8D 3F 28 E5 02 0E A2 58 B8 D6 0F A8 E5 10 EB E8 F1 23 EF 61 E5 E2 54 EA A9 2A 22 AF 17 A1 23 97 9A 1C }

condition:
		$a0 at entrypoint
}
	
	
rule NSPackNortStarSoftwarehttpwwwnsdsncom
{
strings:
		$a0 = { 83 F9 00 74 28 43 8D B5 ?? ?? FF FF 8B 16 56 51 53 52 56 FF 33 FF 73 04 8B 43 08 03 C2 50 FF 95 ?? ?? FF FF 5A 5B 59 5E 83 C3 0C E2 E1 61 9D E9 ?? ?? ?? FF 8B B5 ?? ?? FF FF 0B F6 0F 84 97 00 00 00 8B 95 ?? ?? FF FF 03 F2 83 3E 00 75 0E 83 7E 04 00 75 08 }

condition:
		$a0
}
	
	
rule PEDiminisherv01Teraphy
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 50 E8 02 01 00 00 8B FD 8D 9D 9A 33 40 00 8B 1B 8D 87 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXcom
{
strings:
		$a0 = { B9 ?? ?? BE ?? ?? BF C0 FF FD }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphiv60v70Hint0signature538BD833C0A3006A00E800FFA300A100A30033C0A30033C0A300E8ep_onlyfalseBorlandDelphiv60KOL
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF A1 ?? 72 40 00 33 D2 E8 ?? ?? FF FF A1 ?? 72 40 00 8B 00 83 C0 14 E8 ?? ?? FF FF E8 ?? ?? FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule SEAAXE
{
strings:
		$a0 = { FC BC ?? ?? 0E 1F E8 ?? ?? 26 A1 ?? ?? 8B 1E ?? ?? 2B C3 8E C0 B1 ?? D3 E3 }

condition:
		$a0 at entrypoint
}
	
	
rule Histogramgraphicsfile
{
strings:
		$a0 = { 6D 68 77 61 6E 68 00 04 01 02 01 02 }

condition:
		$a0
}
	
	
rule MicrosoftVisualC30oldcrap
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 ?? ?? 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00 00 83 EC 10 }

condition:
		$a0 at entrypoint
}
	
	
rule UpackV010V011Dwing
{
strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 ?? F3 AB C1 E0 ?? B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C ?? 73 ?? B0 ?? 3C ?? 72 02 2C ?? 50 0F B6 5F FF C1 E3 ?? B3 ?? 8D 1C 5B 8D ?? ?? ?? ?? ?? ?? B0 ?? 67 E3 29 8B D7 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakeMSVC70DLLMethod3emadicius
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB }

condition:
		$a0
}
	
	
rule MicrosoftVisualCv71EXE
{
strings:
		$a0 = { 6A ?? 68 ?? ?? ?? 01 E8 ?? ?? 00 00 66 81 3D 00 00 00 01 4D 5A 75 ?? A1 3C 00 00 01 ?? ?? 00 00 00 01 }

condition:
		$a0 at entrypoint
}
	
	
rule Morphinev12v13
{
strings:
		$a0 = { FF 25 34 ?? 5A 00 8B C0 FF 25 38 ?? 5A 00 8B C0 }

condition:
		$a0
}
	
	
rule SimplePack111Method1bagieTMX
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC F3 A5 89 C1 83 E1 03 F3 A4 5F 5E 8B 04 24 89 EA 03 57 0C E8 3F 01 00 00 58 68 00 40 00 00 FF 77 10 50 FF 93 3C 03 00 00 83 C7 28 4E 75 9E BE ?? ?? ?? ?? 09 F6 0F 84 0C 01 00 00 01 EE 8B 4E 0C 09 C9 0F 84 FF 00 00 00 01 E9 89 CF 57 FF 93 30 03 00 00 09 C0 75 3D 6A 04 68 00 10 00 00 68 00 10 00 00 6A 00 FF 93 38 03 00 00 89 C6 8D 83 6F 02 00 00 57 50 56 FF 93 44 03 00 00 6A 10 6A 00 56 6A 00 FF 93 48 03 00 00 89 E5 }
	$a1 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MASM32
{
strings:
		$a0 = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }

condition:
		$a0 at entrypoint
}
	
	
rule SoftDefenderv10v11
{
strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 ?? ?? ?? ?? 58 05 BA 01 ?? ?? 03 C8 74 BE 75 BC E8 }

condition:
		$a0 at entrypoint
}
	
	
	
rule VcasmProtector1112vcasm
{
strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidiumv1111
{
strings:
		$a0 = { EB 02 ?? ?? E8 E7 1C 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxEddie1530
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? 50 06 56 1E 33 C0 50 1F C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E }

condition:
		$a0 at entrypoint
}
	
	
rule PEncrypt10JunkCode
{
strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 ?? ?? ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 ?? ?? ?? FF }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor22xSoftCompleteDevelopement
{
strings:
		$a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF }

condition:
		$a0
}
	
	
rule PEPasswordv02SMTSMF
{
strings:
		$a0 = { E8 04 ?? ?? ?? 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv16Vaska
{
strings:
		$a0 = { 33 D0 68 ?? ?? ?? ?? FF D2 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	$a1 = { 33 D0 68 ?? ?? ?? ?? FF D2 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule YodasProtectorv1032Beta2AshkbizDanehkar
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule LCCWin32
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 10 30 40 00 68 9A 10 40 }

condition:
		$a0 at entrypoint
}
	
	
rule ESOEclipseOperatingSystemv208DOSExtender
{
strings:
		$a0 = { 8C C8 8E D8 BA ?? ?? E8 ?? ?? BB ?? ?? 8C C0 2B D8 B4 4A CD 21 BA ?? ?? 73 ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule VxMTEnonencrypted
{
strings:
		$a0 = { F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv130Engdulekxt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 09 06 AD 75 DB 8B EC C3 ?? ?? ?? 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack022023betaDwing
{
strings:
		$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 59 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }
	$a1 = { AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 ?? 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }
	$a2 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2
}
	
	
rule AZProtect
{
strings:
		$a0 = { EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01CodeLockAnorganix
{
strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITEv100c1
{
strings:
		$a0 = { 2E 8C 1E ?? ?? 8B 1E ?? ?? 8C DA 81 C2 ?? ?? 3B DA 72 ?? 81 EB ?? ?? 83 EB ?? FA 8E D3 BC ?? ?? FB FD BE ?? ?? 8B FE }

condition:
		$a0 at entrypoint
}
	
	
rule Crunch4BitArts
{
strings:
		$a0 = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITEv100c2
{
strings:
		$a0 = { BA ?? ?? A1 ?? ?? 2D ?? ?? 8C CB 81 C3 ?? ?? 3B C3 77 ?? 05 ?? ?? 3B C3 77 ?? B4 09 BA ?? ?? CD 21 CD 20 90 }

condition:
		$a0 at entrypoint
}
	
	
rule kkrunchyv017FGiesen
{
strings:
		$a0 = { FC FF 4D 08 31 D2 8D 7D 30 BE }

condition:
		$a0
}
	
	
rule ACProtectv190gRiscosoftwareInc
{
strings:
		$a0 = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule theWRAPbyTronDoc
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 48 D2 4B 00 E8 BC 87 F4 FF BB 04 0B 4D 00 33 C0 55 68 E8 D5 4B 00 64 FF 30 64 89 20 E8 9C F4 FF FF E8 F7 FB FF FF 6A 40 8D 55 F0 A1 F0 ED 4B 00 8B 00 E8 42 2E F7 FF 8B 4D F0 B2 01 A1 F4 C2 40 00 E8 F7 20 F5 FF }
	$a1 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 48 D2 4B 00 E8 BC 87 F4 FF BB 04 0B 4D 00 33 C0 55 68 E8 D5 4B 00 64 FF 30 64 89 20 E8 9C F4 FF FF E8 F7 FB FF FF 6A 40 8D 55 F0 A1 F0 ED 4B 00 8B 00 E8 42 2E F7 FF 8B 4D F0 B2 01 A1 F4 C2 40 00 E8 F7 20 F5 FF 8B F0 B2 01 A1 B4 C3 40 00 E8 F1 5B F4 FF 89 03 33 D2 8B 03 E8 42 1E F5 FF 66 B9 02 00 BA FC FF FF FF 8B C6 8B 38 FF 57 0C BA B8 A7 4D 00 B9 04 00 00 00 8B C6 8B 38 FF 57 04 83 3D B8 A7 4D 00 00 0F 84 5E 01 00 00 8B 15 B8 A7 4D 00 83 C2 04 F7 DA 66 B9 02 00 8B C6 8B 38 FF 57 0C 8B 0D B8 A7 4D 00 8B D6 8B 03 E8 2B 1F F5 FF 8B C6 E8 B4 5B F4 FF 33 D2 8B 03 E8 DF 1D F5 FF BA F0 44 4E 00 B9 01 00 00 00 8B 03 8B 30 FF 56 04 80 3D F0 44 4E 00 0A 75 3F BA B8 A7 4D 00 B9 04 00 00 00 8B 03 8B 30 FF 56 04 8B 15 B8 A7 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Obsidium133720070623ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 F7 26 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv2000AlexeySolodovnikov
{
strings:
		$a0 = { 60 E8 70 05 00 00 EB 4C }

condition:
		$a0 at entrypoint
}
	
	
rule Petitev22wwwun4seencompetite
{
strings:
		$a0 = { B8 00 ?0 4? 00 6? 00 ?? ?? 0? ?? ?? ?? ?? ?? 00 00 }
	$a1 = { B8 00 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule Armadillov4000053SiliconRealmsToolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1 4B 00 33 F6 56 E8 78 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 43 13 00 00 FF 15 8C 30 4B 00 A3 A4 B7 4B 00 E8 01 12 00 00 A3 F8 A1 4B 00 E8 AA 0F 00 00 E8 EC 0E 00 00 E8 2D FA FF FF 89 }

condition:
		$a0
}
	
	
rule Upack036betaDwing
{
strings:
		$a0 = { BE E0 11 ?? ?? FF 36 E9 C3 00 00 00 48 01 ?? ?? 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C }

condition:
		$a0
}
	
	
rule AmigaAIFF8SFXAudiofile
{
strings:
		$a0 = { 46 4F 52 4D ?? ?? ?? ?? 38 53 56 58 56 48 44 52 }

condition:
		$a0
}
	
	
rule MicrosoftC19901992
{
strings:
		$a0 = { B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 }
	$a1 = { B8 00 30 CD 21 3C 03 73 ?? 0E 1F BA ?? ?? B4 09 CD 21 06 33 C0 50 CB }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ACProtectUltraProtect10X20XRiSco
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 }
	$a1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 55 53 45 52 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 6F 72 74 5F 45 6E 64 73 73 00 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule Thinstall3035Jtit
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor10betaCGSoftLabs
{
strings:
		$a0 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC }
	$a1 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 2A 70 77 20 3D 20 30 78 25 30 34 78 20 20 2A 70 64 77 20 3D 20 30 78 25 30 38 78 00 00 00 00 00 00 00 00 00 42 61 64 20 70 6F 69 6E 74 65 72 3A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 2A 70 64 77 20 3D 20 30 78 25 30 38 78 00 00 00 45 72 72 6F 72 3A 00 00 54 68 65 20 25 68 73 20 66 69 6C 65 20 69 73 20 0A 6C 69 6E 6B 65 64 20 74 6F 20 6D 69 73 73 69 6E 67 20 65 78 70 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PENinjav10DzAkRAkerTNT
{
strings:
		$a0 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule PESPin13Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

condition:
		$a0
}
	
	
rule RLPackV118DllLZMA430ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtector1031AshkibizDanehlar
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 74 72 42 00 8B D5 81 C2 C3 72 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3F A9 42 00 81 E9 6E 73 42 00 8B D5 81 C2 6E 73 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 98 2E 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptorv13045
{
strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
	$a1 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}

	
	
rule PCPECalphapreview
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule LaunchAnywhere4001
{
strings:
		$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 }

condition:
		$a0
}
	
	
rule AlexProtectorv10Alex
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B }

condition:
		$a0 at entrypoint
}
	
	
rule HitachiRasterFormatgraphicsformat
{
strings:
		$a0 = { 43 41 44 43 2F 4B 52 20 52 53 54 }

condition:
		$a0
}
	
	
rule Shrinkv10
{
strings:
		$a0 = { 50 9C FC BE ?? ?? BF ?? ?? 57 B9 ?? ?? F3 A4 8B ?? ?? ?? BE ?? ?? BF ?? ?? F3 A4 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule BamBamv001
{
strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? 00 A1 2B ?? ?? 00 66 8B 15 2F ?? ?? 00 B9 80 ?? ?? 00 2B CF 89 45 E8 89 0D 6B ?? ?? 00 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0 0F 8E 39 01 00 00 89 45 F0 C6 45 FF 00 8D 7D E8 8B F3 8A 0E 8A 17 8A C1 3A CA 75 1E 84 C0 74 16 8A 56 01 8A 4F 01 8A C2 3A D1 75 0E 83 C6 02 83 C7 02 84 C0 75 DC 33 C0 EB 05 1B C0 83 D8 FF 85 C0 75 04 C6 45 FF 01 8B 43 10 85 C0 0F 84 DD 00 00 00 8B 43 08 50 E8 D7 04 00 00 8A 4D FF 83 C4 04 84 C9 8B 4B 08 89 45 F8 C7 45 F4 00 00 00 00 74 61 8B 15 07 ?? ?? 00 8B 35 6B ?? ?? 00 8B 7B 0C 2B CA 03 F2 8B D1 03 F7 8B F8 C1 E9 02 F3 A5 }

condition:
		$a0
}
	
	
rule AHPack01FEUERRADER
{
strings:
		$a0 = { 60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV1311ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPackv23NorthStar
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 56 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }

condition:
		$a0
}
	
	
rule DxPack10
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 }

condition:
		$a0 at entrypoint
}
	
	
rule Pohernah103byKas
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 2A 27 40 00 31 C0 40 83 F0 06 40 3D 40 1F 00 00 75 07 BE 6A 27 40 00 EB 02 EB EB 8B 85 9E 28 40 00 83 F8 01 75 17 31 C0 01 EE 3D 99 00 00 00 74 0C 8B 8D 86 28 40 00 30 0E 40 46 EB ED }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV1258ObsidiumSoftware
{
strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule nPackv11150200BetaNEOx
{
strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PeCompact2xxSlimLoaderBitSumTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXProtectorv10x2
{
strings:
		$a0 = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }

condition:
		$a0
}
	
	
rule MicrosoftCABSFX
{
strings:
		$a0 = { E8 0A 00 00 00 E9 7A FF FF FF CC CC CC CC CC }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector13Xvcasm
{
strings:
		$a0 = { 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 60 8B B4 24 24 00 00 00 8B BC 24 28 00 00 00 FC C6 C2 80 33 DB A4 C6 C3 02 E8 A9 00 00 00 0F 83 F1 FF FF FF 33 C9 E8 9C 00 00 00 0F 83 2D 00 00 00 33 C0 E8 8F 00 00 00 0F 83 37 00 00 00 C6 C3 02 41 C6 C0 10 E8 7D 00 00 00 10 C0 0F 83 F3 FF FF FF }
	$a1 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 FF FF C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule Packman0001bubba
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeMSVC70DLLMethod3emadiciush
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv108
{
strings:
		$a0 = { 90 75 01 FF E9 }
	$a1 = { 90 90 90 75 01 FF E9 }
	$a2 = { 90 90 75 01 FF E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule eXPressorProtectionV150XCGSoftLabsSignbyfly
{
strings:
		$a0 = { EB 01 68 EB 01 ?? ?? ?? ?? 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 59 59 EB 01 C8 EB 02 66 F0 68 ?? ?? ?? ?? E8 0E 05 00 00 59 EB 01 DD 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 DA 1A 8B 45 F4 0F ?? ?? ?? ?? ?? ?? 33 45 F4 8B 4D F4 88 ?? ?? ?? ?? ?? EB 01 EB EB }

condition:
		$a0
}
	
	
rule UPackv011
{
strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 55 CC 33 C9 E9 DF 00 00 00 8B 5E 0C 83 C2 30 FF D5 73 50 83 C2 30 FF D5 72 1B 83 C2 30 FF D5 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 46 0C B1 80 8A 00 EB CF 83 C2 60 FF D5 87 5E 10 73 0D 83 C2 30 FF D5 87 5E 14 73 03 87 5E 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 96 7C 07 00 00 FF 55 D0 5B 91 EB 77 3C 07 B0 07 72 02 B0 0A 50 87 5E 10 87 5E 14 89 5E 18 8D 96 C4 0B 00 00 FF 55 D0 50 48 }

condition:
		$a0
}
	
	
rule PEEncryptv40bJunkCode
{
strings:
		$a0 = { 66 ?? ?? 00 66 83 ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv30EXE_LZMAMarkusOberhumerLaszloMolnarJohnReiser
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 57 83 C3 04 53 68 ?? ?? ?? 00 56 }

condition:
		$a0 at entrypoint
}
	
	
rule PEQuake006forgat
{
strings:
		$a0 = { E8 A5 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? ?? 00 5B ?? ?? 00 6E ?? ?? 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule VBOXv42MTE
{
strings:
		$a0 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }

condition:
		$a0 at entrypoint
}
	
	
rule Kryptonv02
{
strings:
		$a0 = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }

condition:
		$a0 at entrypoint
}
	
	
rule D1S1Gv11BetaScrambledEXED1N
{
strings:
		$a0 = { E8 07 00 00 00 E8 1E 00 00 00 C3 90 58 89 C2 89 C2 25 00 F0 FF FF 50 83 C0 55 8D 00 FF 30 8D 40 04 FF 30 52 C3 8D 40 00 55 8B EC 83 C4 E8 53 56 57 8B 4D 10 8B 45 08 89 45 F8 8B 45 0C 89 45 F4 8D 41 61 8B 38 8D 41 65 8B 00 03 C7 89 45 FC 8D 41 69 8B 00 03 C7 8D 51 6D 8B 12 03 D7 83 C1 71 8B 09 03 CF 2B CA 72 0A 41 87 D1 80 31 FF 41 4A 75 F9 89 45 F0 EB 71 8B }

condition:
		$a0
}
	
	
rule ACProtect109gRiscosoftwareInc
{
strings:
		$a0 = { 60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule NorthStarPEShrinker13Liuxingping
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorV13CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV118LZMA430ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 }

condition:
		$a0 at entrypoint
}
	
	
rule MSRunTimeLibrary198804
{
strings:
		$a0 = { 1E B8 ?? ?? 8E D8 B4 30 CD 21 3C 02 73 ?? BA ?? ?? E8 ?? ?? 06 33 C0 50 CB }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoinerSmallbuild035GlOFF
{
strings:
		$a0 = { 51 33 CB 86 C9 59 E8 9E FD FF FF 66 87 DB 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MEW11SE10Northfox
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C 00 }

condition:
		$a0
}
	
	
rule Upack020betaDwing
{
strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 }

condition:
		$a0 at entrypoint
}
	
	
rule WindowsType1fontmetricfile
{
strings:
		$a0 = { 00 01 ?? ?? 00 00 43 6F 70 79 72 69 67 68 74 20 }

condition:
		$a0
}
	
	
rule UPX20030XMarkusOberhumerLaszloMolnarJohnReiser
{
strings:
		$a0 = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF }

condition:
		$a0
}
	
	
rule UnnamedScrambler12Bp0ke
{
strings:
		$a0 = { 55 8B EC 83 C4 D8 53 56 57 33 C0 89 45 D8 89 45 DC 89 45 E0 89 45 E4 89 45 E8 B8 70 3A 40 00 E8 C4 EC FF FF 33 C0 55 68 5C 3F 40 00 64 FF 30 64 89 20 E8 C5 D7 FF FF E8 5C F5 FF FF B8 20 65 40 00 33 C9 BA 04 01 00 00 E8 D3 DB FF FF 68 04 01 00 00 68 20 65 }
	$a1 = { 55 8B EC 83 C4 D8 53 56 57 33 C0 89 45 D8 89 45 DC 89 45 E0 89 45 E4 89 45 E8 B8 70 3A 40 00 E8 C4 EC FF FF 33 C0 55 68 5C 3F 40 00 64 FF 30 64 89 20 E8 C5 D7 FF FF E8 5C F5 FF FF B8 20 65 40 00 33 C9 BA 04 01 00 00 E8 D3 DB FF FF 68 04 01 00 00 68 20 65 40 00 6A 00 FF 15 10 55 40 00 BA 6C 3F 40 00 B8 14 55 40 00 E8 5A F4 FF FF 85 C0 0F 84 1B 04 00 00 BA 18 55 40 00 8B 0D 14 55 40 00 E8 16 D7 FF FF 8B 05 88 61 40 00 8B D0 B8 54 62 40 00 E8 D4 E3 FF FF B8 54 62 40 00 E8 F2 E2 FF FF 8B D0 B8 18 55 40 00 8B 0D 88 61 40 00 E8 E8 D6 FF FF FF 35 34 62 40 00 FF 35 30 62 40 00 FF 35 3C 62 40 00 FF 35 38 62 40 00 8D 55 E8 A1 88 61 40 00 E8 E3 F0 FF FF 8B 55 E8 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule DMarkDatabasefile
{
strings:
		$a0 = { 33 44 4D 61 72 6B 20 44 61 74 61 62 61 73 65 20 46 69 6C 65 }

condition:
		$a0
}
	
	
rule RSCsProcessPatcher151
{
strings:
		$a0 = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 }

condition:
		$a0
}
	
	
rule LauncherGeneratorv103
{
strings:
		$a0 = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 74 51 C1 E0 02 A3 5C 20 40 00 BB 70 21 40 00 03 C3 8B 18 68 60 20 40 00 53 B8 F0 21 40 00 03 05 5C 20 40 00 8B D8 8B 03 05 70 20 40 00 50 B8 70 22 40 00 03 05 5C 20 40 00 FF 30 FF 35 00 20 40 00 E8 26 00 00 00 A1 58 20 40 00 40 A3 58 20 40 00 EB A2 6A FF E8 00 00 00 00 FF 25 5C 30 40 00 FF 25 60 30 40 00 FF 25 64 30 40 00 FF 25 68 30 40 00 FF 25 6C 30 40 00 FF 25 74 30 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule yodasProtector102103AshkbizDanehkar
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePESHiELD025emadicius
{
strings:
		$a0 = { 60 E8 2B 00 00 00 0D 0A 0D 0A 0D 0A 52 65 67 69 73 74 41 72 65 64 20 74 6F 3A 20 4E 4F 4E 2D 43 4F 4D 4D 45 52 43 49 41 4C 21 21 0D 0A 0D 0A 0D 00 58 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 }

condition:
		$a0
}
	
	
rule diProtector1xdiProtectorSoftware
{
strings:
		$a0 = { 01 00 A0 E3 14 00 00 EB 00 00 20 E0 44 10 9F E5 03 2A A0 E3 40 30 A0 E3 AE 00 00 EB 30 00 8F E5 00 20 A0 E1 3A 0E 8F E2 00 00 80 E2 1C 10 9F E5 20 30 8F E2 0E 00 00 EB 14 00 9F E5 14 10 9F E5 7F 20 A0 E3 C5 00 00 EB 04 C0 8F E2 00 F0 9C E5 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv080
{
strings:
		$a0 = { 60 E8 F9 11 00 00 C3 83 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01YodasProtector102Anorganix
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 90 90 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector11Xvcasm
{
strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1304ObsidiumSoftwareh
{
strings:
		$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 }

condition:
		$a0
}
	
	
rule BDCHelpSystemHelpfile
{
strings:
		$a0 = { 42 44 43 20 48 65 6C 70 53 79 73 74 65 6D }

condition:
		$a0
}
	
	
rule yP10bbyAshkbizDanehkar
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 C2 E8 03 00 00 00 EB 01 ?? AC ?? ?? ?? ?? ?? ?? ?? EB 01 E8 }

condition:
		$a0
}
	
	
rule EXE2COMregular
{
strings:
		$a0 = { E9 8C CA 81 C3 ?? ?? 3B 16 ?? ?? 76 ?? BA ?? ?? B4 09 CD 21 CD 20 0D }

condition:
		$a0 at entrypoint
}
	
	
rule TrilobytesJPEGgraphicsLibrary
{
strings:
		$a0 = { 84 10 FF FF FF FF 1E 00 01 10 08 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule Themida1201compressedOreansTechnologiesh
{
strings:
		$a0 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
	$a1 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? 00 03 C7 B9 ?? ?? ?? 00 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01 00 00 02 00 00 00 91 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Pohernah102byKas
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED DE 26 40 00 8B BD 05 28 40 00 8B 8D 0D 28 40 00 B8 25 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 09 28 40 00 31 C0 51 31 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 09 28 40 00 8B 85 11 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 25 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 01 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv20HideEPVaska
{
strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov172v173
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv108x
{
strings:
		$a0 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }

condition:
		$a0 at entrypoint
}
	
	
rule AsCryptv01SToRM3
{
strings:
		$a0 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 51 ?? ?? ?? 01 00 00 00 83 ?? ?? E2 }

condition:
		$a0
}
	
	
rule ASProtectV2XDLLAlexeySolodovnikov
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeyodascryptor12emadiciush
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC 90 2C 8A C0 C0 78 90 04 62 EB 01 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule YZPack12UsAr
{
strings:
		$a0 = { 4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Neolitev20
{
strings:
		$a0 = { E9 A6 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01NorthStarPEShrinker13Anorganix
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PasswordprotectormySMT
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 8B FD 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 46 80 ?? ?? 74 }

condition:
		$a0 at entrypoint
}
	
	
rule ReflexiveArcadeWrapper
{
strings:
		$a0 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 }
	$a1 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 42 00 33 F6 56 E8 58 43 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 23 40 00 00 FF 15 18 51 42 00 A3 44 FE 42 00 E8 E1 3E 00 00 A3 78 E8 42 00 E8 8A 3C 00 00 E8 CC 3B 00 00 E8 3E F5 FF FF 89 75 D0 8D 45 A4 50 FF 15 14 51 42 00 E8 5D 3B 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 10 51 42 00 50 E8 0D 6E FE FF 89 45 A0 50 E8 2C F5 FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 9B 39 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 1E F5 FF FF 83 3D 80 E8 42 00 01 75 05 E8 F3 43 00 00 FF 74 24 04 E8 23 44 00 00 68 FF 00 00 00 FF 15 B0 B8 42 00 59 59 C3 83 3D 80 E8 42 00 01 75 05 E8 CE 43 00 00 FF 74 24 04 E8 FE 43 00 00 59 68 FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PseudoSigner01BorlandDelphi50KOLMCK
{
strings:
		$a0 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule HyingsPEArmor076HyingCCG
{
strings:
		$a0 = { 01 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 56 69 72 74 75 61 6C 46 72 65 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 ?? ?? ?? 59 ?? ?? ?? ?? 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 8D ?? ?? ?? ?? 00 00 00 00 00 00 00 9D ?? ?? ?? 8D ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 00 08 00 00 00 00 00 00 00 60 E8 00 00 00 00 5D 81 ED F0 00 00 00 8D B5 07 01 00 00 55 56 81 C5 ?? ?? ?? ?? 55 C3 }

condition:
		$a0
}
	
	
rule Upackv030betaDwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 }

condition:
		$a0 at entrypoint
}
	
	
rule VxACMEClonewarMutant
{
strings:
		$a0 = { FC AD 3D FF FF 74 20 E6 42 8A C4 E6 42 E4 61 0C 03 E6 61 AD B9 40 1F E2 FE }

condition:
		$a0 at entrypoint
}
	
	
rule Mew11SEv12EngNorthfox
{
strings:
		$a0 = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C }

condition:
		$a0 at entrypoint
}
	
	
rule TPACKv05cm1
{
strings:
		$a0 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 8E FE }

condition:
		$a0 at entrypoint
}
	
	
rule TPACKv05cm2
{
strings:
		$a0 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv305c4Extractable
{
strings:
		$a0 = { 03 05 00 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualBasicv50v60
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 ?? 00 00 00 30 ?? 00 }
	$a1 = { FF 25 ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF }
	$a2 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 00 00 00 00 30 00 00 00 }

condition:
		$a0 or $a1 or $a2 at entrypoint
}
	
	
rule ExeJoiner10Yodaf2f
{
strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 }
	$a1 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 E8 E2 02 00 00 83 F8 FF 0F 84 6D 02 00 00 A3 0C 12 40 00 8B D8 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 E3 02 00 00 6A 00 68 3C 12 40 00 6A 04 68 1E 12 40 00 FF 35 08 12 40 00 E8 C4 02 00 00 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 B7 02 00 00 6A 00 68 3C 12 40 00 6A 04 68 1A 12 40 00 FF 35 08 12 40 00 E8 98 02 00 00 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 8B 02 00 00 6A 00 68 3C 12 40 00 6A 04 68 34 12 40 00 FF 35 08 12 40 00 E8 6C 02 00 00 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 5F 02 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule WebCopsDLL
{
strings:
		$a0 = { A8 BE 58 DC D6 CC C4 63 4A 0F E0 02 BB CE F3 5C 50 23 FB 62 E7 3D 2B }

condition:
		$a0 at entrypoint
}
	
	
rule Morphine33SilentSoftwareSilentShieldc2005h
{
strings:
		$a0 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 }

condition:
		$a0
}
	
	
rule MacromediaWindowsFlashProjectorPlayerv30
{
strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftWindowsShortcutfile
{
strings:
		$a0 = { 4C 00 00 00 01 14 02 00 00 00 }

condition:
		$a0
}
	
	
rule PESpinV11cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV112V114aPlib043ap0xSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }

condition:
		$a0 at entrypoint
}
	
	
rule CGMGraphicsformat
{
strings:
		$a0 = { 00 2A 08 48 69 4A 61 61 6B 20 32 }

condition:
		$a0
}
	
	
rule MicrosoftVisualC80Debug
{
strings:
		$a0 = { E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 }
	$a1 = { E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RLPack118aPlib043ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule DotFixNiceProtectvna
{
strings:
		$a0 = { 60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv032betaDwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 }

condition:
		$a0 at entrypoint
}
	
	
rule PackItBitch10archphase
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 28 ?? ?? ?? 35 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 ?? ?? ?? 50 ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? ?? ?? 79 ?? ?? ?? 7D ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule JDPack2xJDPack
{
strings:
		$a0 = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RPolyCryptv10personalpolycryptorsignfrompinch
{
strings:
		$a0 = { 50 58 97 97 60 61 8B 04 24 80 78 F3 6A E8 00 00 00 00 58 E8 00 00 00 00 58 91 91 EB 00 0F 85 6B F4 76 6F E8 00 00 00 00 83 C4 04 E8 00 00 00 00 58 90 E8 00 00 00 00 83 C4 04 8B 04 24 80 78 F1 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv031betaDwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01PEPack099Anorganix
{
strings:
		$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Morphine33Holy_FatherRatter29A
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 }

condition:
		$a0
}
	
	
rule EXECryptor239minimumprotection
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? FF 50 C1 C8 18 89 05 ?? ?? ?? ?? C3 C1 C0 18 51 E9 ?? ?? ?? FF 84 C0 0F 84 6A F9 FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF E8 CF E9 FF FF B8 01 00 00 00 E9 ?? ?? ?? FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 ?? ?? ?? FF 84 C0 0F 84 8E EC FF FF E9 ?? ?? ?? FF C3 87 3C 24 5F 8B 00 03 45 FC 83 C0 18 E9 ?? ?? ?? FF 87 0C 24 59 B8 01 00 00 00 D3 E0 23 D0 E9 02 18 00 00 0F 8D DB 00 00 00 C1 E8 14 E9 CA 00 00 00 9D 87 0C 24 59 87 1C 24 68 AE 73 B9 96 E9 C5 10 00 00 0F 8A ?? ?? ?? ?? E9 ?? ?? ?? FF 81 FD F5 FF 8F 07 E9 4F 10 00 00 C3 E9 5E 12 00 00 87 3C 24 E9 ?? ?? ?? FF E8 ?? ?? ?? FF 83 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 8D 55 EC B8 ?? ?? ?? ?? E9 ?? ?? ?? FF E8 A7 1A 00 00 E8 2A CB FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF 59 89 45 E0 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMicrosoftVisualC60ASM
{
strings:
		$a0 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }

condition:
		$a0 at entrypoint
}
	
	
rule HaspdongleAlladin
{
strings:
		$a0 = { 50 53 51 52 57 56 8B 75 1C 8B 3E ?? ?? ?? ?? ?? 8B 5D 08 8A FB ?? ?? 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF 32 }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITEv112v115v1201
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 73 ?? 2D ?? ?? FA 8E D0 FB 2D ?? ?? 8E C0 50 B9 ?? ?? 33 FF 57 BE ?? ?? FC F3 A5 CB B4 09 BA ?? ?? CD 21 CD 20 }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITEv112v115v1202
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 3B C4 73 }

condition:
		$a0 at entrypoint
}
	
	
rule UnknownbySMT
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 83 ?? ?? 57 EB }

condition:
		$a0 at entrypoint
}
	
	
rule Petite22c199899IanLuckh
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66 83 C7 68 81 C6 ?? ?? 00 00 F3 A5 FF D3 58 8D 90 B8 01 00 00 8B 0A 0F BA F1 1F 73 16 8B 04 24 FD 8B F0 8B F8 03 72 04 03 7A 08 F3 A5 83 C2 0C FC EB E2 83 C2 10 8B 5A F4 85 DB 74 D8 8B 04 24 8B 7A F8 03 F8 52 8D 34 01 EB 17 58 58 58 5A 74 C4 E9 1C FF FF FF 02 D2 75 07 8A 16 83 EE FF 12 D2 C3 81 FB 00 00 01 00 73 0E 68 60 C0 FF FF 68 60 FC FF FF B6 05 EB 22 81 FB 00 00 04 00 73 0E 68 80 81 FF FF 68 80 F9 FF FF B6 07 EB 0C 68 00 83 FF FF 68 00 FB FF FF B6 08 6A 00 32 D2 4B A4 33 C9 83 FB 00 7E A4 E8 AA FF FF FF 72 17 A4 30 5F FF 4B EB ED 41 E8 9B FF FF FF 13 C9 E8 94 FF FF FF 72 F2 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptorv153
{
strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

condition:
		$a0
}
	
	
rule ORiENV1XV2XFisunAVSignbyfly
{
strings:
		$a0 = { 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D }

condition:
		$a0
}
	
	
rule ObsidiumV1342ObsidiumSoftwarenbspnbspSignByfly
{
strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 C3 27 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule eXpressorv11CGSoftLabs
{
strings:
		$a0 = { E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule TurboPascalHelpFile
{
strings:
		$a0 = { 54 55 52 ?? ?? ?? 50 41 53 ?? ?? ?? ?? 48 45 4C 50 }

condition:
		$a0
}
	
	
rule NsPackV11LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RECSmallv102
{
strings:
		$a0 = { 8C D8 1E E8 ?? ?? 83 ?? ?? 5D B9 ?? ?? 81 ?? ?? ?? 40 8E D8 2B DB B2 ?? ?? ?? FE C2 43 83 }

condition:
		$a0 at entrypoint
}
	
	
rule PrivatePersonalPackerPPPv102ConquestOfTroycom
{
strings:
		$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxHorse1776
{
strings:
		$a0 = { E8 ?? ?? 5D 83 ?? ?? 06 1E 26 ?? ?? ?? ?? BF ?? ?? 1E 0E 1F 8B F7 01 EE B9 ?? ?? FC F3 A6 1F 1E 07 }

condition:
		$a0 at entrypoint
}
	
	
rule DrWebVirusFindingEngineInSoftEDVSysteme
{
strings:
		$a0 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }

condition:
		$a0 at entrypoint
}
	
	
rule RECryptv07xCruddRET
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B }
	$a1 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PESpinv07Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 88 39 40 00 8B 42 3C 03 C2 89 85 92 39 40 00 EB 01 DB 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D A6 39 40 00 53 8F 85 4A 38 40 00 BB ?? 00 00 00 B9 EC 0A 00 00 8D BD 36 3A 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 56 44 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 B3 5F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D 99 39 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftCv104
{
strings:
		$a0 = { FA B8 ?? ?? 8E D8 8E D0 26 8B ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 04 D3 E3 EB }

condition:
		$a0 at entrypoint
}
	
	
rule TurboBATv31050
{
strings:
		$a0 = { BA ?? ?? B4 09 ?? ?? 06 B8 ?? ?? 8E C0 B9 ?? ?? 26 ?? ?? ?? ?? 80 ?? ?? 26 ?? ?? ?? 24 0F 3A C4 ?? ?? 26 ?? ?? ?? 24 0F 3A C4 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv15PrivateVaska
{
strings:
		$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 at entrypoint
}
	
	
rule VxDoom666
{
strings:
		$a0 = { E8 ?? ?? ?? 5E 83 EE ?? B8 CF 7B CD 21 3D CF 7B ?? ?? 0E 1F 81 C6 ?? ?? BF ?? ?? B9 ?? ?? FC F3 A4 06 1F 06 B8 ?? ?? 50 CB B4 48 BB 2C 00 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule NeoLitev200
{
strings:
		$a0 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 }

condition:
		$a0 at entrypoint
}
	
	
rule FASM15x
{
strings:
		$a0 = { 6A 00 FF 15 ?? ?? 40 00 A3 ?? ?? 40 00 }

condition:
		$a0
}
	
	
rule PseudoSigner02FSG131
{
strings:
		$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }

condition:
		$a0 at entrypoint
}
	
	
rule TurboC1987
{
strings:
		$a0 = { FB 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA }

condition:
		$a0 at entrypoint
}
	
	
rule Crunch5Fusion4
{
strings:
		$a0 = { EB 15 03 ?? ?? ?? 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 55 E8 }

condition:
		$a0
}
	
	
rule ThinstallVirtualizationSuiteV3049V3080ThinstallCompany
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Hasp4envelopedongleAlladin
{
strings:
		$a0 = { 10 02 D0 51 0F 00 83 }

condition:
		$a0 at entrypoint
}
	
	
rule SDC12SelfDecryptingBinaryGeneratorbyClaesMNyberg
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 A0 91 40 00 E8 DB FE FF FF 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 3B 3D 8D 00 00 C0 72 4B BB 01 00 00 00 C7 44 24 04 00 00 00 00 C7 04 24 08 00 00 00 E8 CE 24 00 00 83 F8 01 0F 84 C4 00 00 }
	$a1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 A0 91 40 00 E8 DB FE FF FF 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 3B 3D 8D 00 00 C0 72 4B BB 01 00 00 00 C7 44 24 04 00 00 00 00 C7 04 24 08 00 00 00 E8 CE 24 00 00 83 F8 01 0F 84 C4 00 00 00 85 C0 0F 85 A9 00 00 00 31 C0 83 C4 14 5B 5D C2 04 00 3D 94 00 00 C0 74 56 3D 96 00 00 C0 74 1E 3D 93 00 00 C0 75 E1 EB B5 3D 05 00 00 C0 8D B4 26 00 00 00 00 74 43 3D 1D 00 00 C0 75 CA C7 44 24 04 00 00 00 00 C7 04 24 04 00 00 00 E8 73 24 00 00 83 F8 01 0F 84 99 00 00 00 85 C0 74 A9 C7 04 24 04 00 00 00 FF D0 B8 FF FF FF FF EB 9B 31 DB 8D 74 26 00 E9 69 FF FF FF C7 44 24 04 00 00 00 00 C7 04 24 0B 00 00 00 E8 37 24 00 00 83 F8 01 74 7F 85 C0 0F 84 6D FF FF FF C7 04 24 0B 00 00 00 8D 76 00 FF D0 B8 FF FF FF FF E9 59 FF FF FF C7 04 24 08 00 00 00 FF D0 B8 FF FF FF FF E9 46 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 08 00 00 00 E8 ED 23 00 00 B8 FF FF FF FF 85 DB 0F 84 25 FF FF FF E8 DB 15 00 00 B8 FF FF FF FF E9 16 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 04 00 00 00 E8 BD 23 00 00 B8 FF FF FF FF E9 F8 FE FF FF C7 44 24 04 01 00 00 00 C7 04 24 0B 00 00 00 E8 9F 23 00 00 B8 FF FF FF FF E9 DA FE FF FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PEMangle
{
strings:
		$a0 = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv20MarkusLaszloReiserh
{
strings:
		$a0 = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 }
	$a1 = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }

condition:
		$a0 or $a1
}
	
	
rule RLPackV10betaap0xSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualC8
{
strings:
		$a0 = { E8 ?? ?? 00 00 E9 ?? ?? FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule mPACKv002DeltaAzizh
{
strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 E8 AA 00 00 00 4E ?? ?? 00 00 00 00 00 00 00 00 00 5E ?? ?? 00 4E ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 ?? ?? ?? 0C ?? ?? ?? CC E4 ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 5D 68 00 FE 9F 07 53 E8 5D 00 00 00 EB FF 71 E8 C2 50 00 EB D6 5E F3 68 89 74 24 48 74 24 58 FF 8D 74 24 58 5E 83 C6 4C 75 F4 59 8D 71 E8 75 09 81 F6 EB FF 51 B9 01 00 83 EE FC 49 FF 71 C7 75 19 8B 74 24 00 00 81 36 50 56 8B 36 EB FF 77 C4 36 81 F6 EB 87 34 24 8B 8B 1C 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 5B EB FF F3 EB FF C3 83 EB FD }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv302v302av304Relocationspack
{
strings:
		$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }

condition:
		$a0 at entrypoint
}
	
	
rule UPXProtectorv10x
{
strings:
		$a0 = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }

condition:
		$a0 at entrypoint
}
	
	
rule SimpleUPXCryptorv3042005Onelayerencryption
{
strings:
		$a0 = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule EXE2COMWithCRCcheck
{
strings:
		$a0 = { B3 ?? B9 ?? ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 43 49 32 E4 03 D0 E3 }

condition:
		$a0 at entrypoint
}
	
	
rule ZortechCv20019881989
{
strings:
		$a0 = { FA B8 ?? ?? 8E D8 8C ?? ?? ?? 26 8B ?? ?? ?? 89 1E ?? ?? 8B D8 2B 1E ?? ?? 89 1E }

condition:
		$a0 at entrypoint
}
	
	
rule CodeCryptv015b
{
strings:
		$a0 = { E9 31 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystemv198
{
strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv100
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }

condition:
		$a0 at entrypoint
}
	
	
rule KGCryptvxx
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 64 A1 30 ?? ?? ?? 84 C0 74 ?? 64 A1 20 ?? ?? ?? 0B C0 74 }

condition:
		$a0 at entrypoint
}
	
	
rule VxKBDflags1024
{
strings:
		$a0 = { 8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22 }

condition:
		$a0 at entrypoint
}
	
	
rule JARArchive
{
strings:
		$a0 = { 1A 4A 61 72 1B }

condition:
		$a0
}
	
	
rule WARNINGTROJANXiaoHui
{
strings:
		$a0 = { 60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1311ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv20
{
strings:
		$a0 = { 53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75 }

condition:
		$a0 at entrypoint
}
	
	
rule CopyControlv303
{
strings:
		$a0 = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }

condition:
		$a0 at entrypoint
}
	
	
rule PEiDBundleV102DLLBoBBobSoft
{
strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule HideProtect1016SoftWarCompany
{
strings:
		$a0 = { 90 90 90 E9 D8 ?? 05 00 95 ?? 53 00 95 4A 50 00 }

condition:
		$a0 at entrypoint
}
	
	
rule AprogrambyJupiter
{
strings:
		$a0 = { 2B C0 74 05 68 ?? ?? ?? ?? 50 }

condition:
		$a0 at entrypoint
}
	
	
rule MEGALITEv120a
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 2D 73 ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 90 }

condition:
		$a0 at entrypoint
}
	
	
rule JExeCompressor10byArashVeyskarami
{
strings:
		$a0 = { 8D 2D D3 4A E5 14 0F BB F7 0F BA E5 73 0F AF D5 8D 0D 0C 9F E6 11 C0 F8 EF F6 DE 80 DC 5B F6 DA 0F A5 C1 0F C1 F1 1C F3 4A 81 E1 8C 1F 66 91 0F BE C6 11 EE 0F C0 E7 33 D9 64 F2 C0 DC 73 0F C0 D5 55 8B EC BA C0 1F 41 00 8B C2 B9 97 00 00 00 80 32 79 50 B8 }
	$a1 = { 8D 2D D3 4A E5 14 0F BB F7 0F BA E5 73 0F AF D5 8D 0D 0C 9F E6 11 C0 F8 EF F6 DE 80 DC 5B F6 DA 0F A5 C1 0F C1 F1 1C F3 4A 81 E1 8C 1F 66 91 0F BE C6 11 EE 0F C0 E7 33 D9 64 F2 C0 DC 73 0F C0 D5 55 8B EC BA C0 1F 41 00 8B C2 B9 97 00 00 00 80 32 79 50 B8 02 00 00 00 50 03 14 24 58 58 51 2B C9 B9 01 00 00 00 83 EA 01 E2 FB 59 E2 E1 FF E0 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Upackv032BetaSignbyhot_UNP
{
strings:
		$a0 = { BE 88 01 ?? ?? AD 50 ?? ?? AD 91 F3 A5 }
	$a1 = { BE 88 01 ?? ?? AD 50 ?? AD 91 ?? F3 A5 }

condition:
		$a0 or $a1
}
	
	
rule yzpackV20UsArSignbyfly
{
strings:
		$a0 = { 25 ?? ?? ?? ?? 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3C AA EB DC FF 54 24 04 2B CB 75 0F FF 54 24 08 EB 27 AC D1 E8 74 30 13 C9 EB 1B 91 48 C1 E0 08 AC FF 54 24 08 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 99 BD ?? ?? ?? ?? FF 65 28 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo430aSiliconRealmsToolworks
{
strings:
		$a0 = { 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43 }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePackV12build3009Method2bagie
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 86 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv038betaDwing
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 97 FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F }

condition:
		$a0 at entrypoint
}
	
	
rule NakedPacker10byBigBoote
{
strings:
		$a0 = { 60 FC 0F B6 05 34 ?? ?? ?? 85 C0 75 31 B8 50 ?? ?? ?? 2B 05 04 ?? ?? ?? A3 30 ?? ?? ?? A1 00 ?? ?? ?? 03 05 30 ?? ?? ?? A3 38 ?? ?? ?? E8 9A 00 00 00 A3 50 ?? ?? ?? C6 05 34 ?? ?? ?? 01 83 3D 50 ?? ?? ?? 00 75 07 61 FF 25 38 ?? ?? ?? 61 FF 74 24 04 6A 00 }
	$a1 = { 60 FC 0F B6 05 34 ?? ?? ?? 85 C0 75 31 B8 50 ?? ?? ?? 2B 05 04 ?? ?? ?? A3 30 ?? ?? ?? A1 00 ?? ?? ?? 03 05 30 ?? ?? ?? A3 38 ?? ?? ?? E8 9A 00 00 00 A3 50 ?? ?? ?? C6 05 34 ?? ?? ?? 01 83 3D 50 ?? ?? ?? 00 75 07 61 FF 25 38 ?? ?? ?? 61 FF 74 24 04 6A 00 FF 15 44 ?? ?? ?? 50 FF 15 40 ?? ?? ?? C3 FF 74 24 04 6A 00 FF 15 44 ?? ?? ?? 50 FF 15 48 ?? ?? ?? C3 8B 4C 24 04 56 8B 74 24 10 57 85 F6 8B F9 74 0D 8B 54 24 10 8A 02 88 01 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule DCryptPrivate09bdrmist
{
strings:
		$a0 = { B9 ?? ?? ?? 00 E8 00 00 00 00 58 68 ?? ?? ?? 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3 }

condition:
		$a0 at entrypoint
}
	
	
rule SkDUndetectabler3NoFSG2MethodSkD
{
strings:
		$a0 = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 00 00 EB 0F 8B 8D F4 FD FF FF 83 C1 01 89 8D F4 FD FF FF 8B 95 F4 FD FF FF 3B 15 ?? 16 00 01 73 1C 8B 85 F4 FD FF FF 8B 0D ?? 16 00 01 8D 54 01 07 81 FA 74 10 00 01 75 02 EB 02 EB C7 8B 85 F4 FD FF FF 50 E8 ?? 00 00 00 83 C4 04 89 85 F0 FD FF FF 8B 8D F0 FD FF FF 89 4D FC C7 45 F8 00 00 00 00 EB 09 8B 55 F8 83 C2 01 89 55 F8 8B 45 F8 3B 85 F4 FD FF FF 73 15 8B 4D FC 03 4D F8 8B 15 ?? 16 00 01 03 55 F8 8A 02 88 01 EB D7 83 3D ?? 16 00 01 00 74 }

condition:
		$a0 at entrypoint
}
	
	
rule NTPacker10ErazerZ
{
strings:
		$a0 = { 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 8D 4D EC BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FC FF FF 8B 55 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 8D 4D E8 BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FE FF FF 8B 55 E8 B8 ?? ?? 40 00 E8 ?? ?? FF FF B8 ?? ?? 40 00 E8 ?? FB FF FF 8B D8 A1 ?? ?? 40 00 BA ?? ?? 40 00 E8 ?? ?? FF FF 75 26 8B D3 A1 ?? ?? 40 00 E8 ?? ?? FF FF 84 C0 75 2A 8D 55 E4 33 C0 E8 ?? ?? FF FF 8B 45 E4 8B D3 E8 ?? ?? FF FF EB 14 8D 55 E0 33 C0 E8 ?? ?? FF FF 8B 45 E0 8B D3 E8 ?? ?? FF FF 6A 00 E8 ?? ?? FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? 40 00 8D 45 E0 BA 04 00 00 00 E8 ?? ?? FF FF C3 E9 ?? ?? FF FF EB EB 5B E8 ?? ?? FF FF 00 00 00 FF FF FF FF 01 00 00 00 25 00 00 00 FF FF FF FF 01 00 00 00 5C 00 00 00 FF FF FF FF 06 00 00 00 53 45 52 56 45 52 00 00 FF FF FF FF 01 00 00 00 31 }

condition:
		$a0 at entrypoint
}
	
	
rule FishPEShield116HellFish
{
strings:
		$a0 = { 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00 ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 00 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 40 }

condition:
		$a0 at entrypoint
}
	
	
rule Com4mailv10
{
strings:
		$a0 = { 42 45 47 49 4E 3D 3D 3D 74 66 75 64 23 6F 66 5F 43 6F 6D 34 4D 61 69 6C 5F 66 69 6C 65 23 0D 0A }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv104b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectv123RC4build0807exeAlexeySolodovnikovh
{
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }

condition:
		$a0
}
	
	
rule VxGotcha879
{
strings:
		$a0 = { E8 ?? ?? 5B 81 EB ?? ?? 9C FC 2E ?? ?? ?? ?? ?? ?? ?? 8C D8 05 ?? ?? 2E ?? ?? ?? ?? 50 2E ?? ?? ?? ?? ?? ?? 8B C3 05 ?? ?? 8B F0 BF 00 01 B9 20 00 F3 A4 0E B8 00 01 50 B8 DA DA CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule MZ0oPE106bTaskFall
{
strings:
		$a0 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 }
	$a1 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 }
	$a2 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4C 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule ExeShieldProtectorV36wwwexeshieldcom
{
strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC }

condition:
		$a0 at entrypoint
}
	
	
rule GenteeInstallerCustom
{
strings:
		$a0 = { 55 8B EC 81 EC 14 04 00 00 53 56 57 6A 00 FF 15 08 41 40 00 68 00 50 40 00 FF 15 04 41 40 00 85 C0 74 29 6A 00 A1 00 20 40 00 ?? ?? ?? ?? 41 40 00 8B F0 6A 06 56 FF 15 1C 41 40 00 6A 03 56 FF }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtector10bAshkbizDanehkarh
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01 }

condition:
		$a0
}
	
	
rule STProtectorV15SilentSoftware
{
strings:
		$a0 = { 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 }

condition:
		$a0
}
	
	
rule Upack_PatchoranyVersionSignbyhot_UNP
{
strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV119LZMA430ap0xSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV22XV2308JititSignbyfly
{
strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor226minimumprotection
{
strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 E8 ?? ?? ?? 00 89 45 F8 E9 ?? ?? ?? ?? 0F 83 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 14 24 5A 57 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 58 81 C0 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 81 C8 ?? ?? ?? ?? 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? ?? C3 BF ?? ?? ?? ?? 81 CB ?? ?? ?? ?? BA ?? ?? ?? ?? 52 E9 ?? ?? ?? 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 34 24 5E 66 8B 00 66 25 ?? ?? E9 ?? ?? ?? ?? 8B CD 87 0C 24 8B EC 51 89 EC 5D 8B 05 ?? ?? ?? ?? 09 C0 E9 ?? ?? ?? ?? 59 81 C1 ?? ?? ?? ?? C1 C1 ?? 23 0D ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? E9 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 13 D0 0B F9 E9 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 64 24 08 31 C0 64 8F 05 00 00 00 00 5A E9 ?? ?? ?? ?? 3C A4 0F 85 ?? ?? ?? 00 8B 45 FC 66 81 38 ?? ?? 0F 84 05 00 00 00 E9 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 3C 24 5F 31 DB 31 C9 31 D2 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 89 45 FC 33 C0 89 45 F4 83 7D FC 00 E9 ?? ?? ?? ?? 53 52 8B D1 87 14 24 81 C0 ?? ?? ?? ?? 0F 88 ?? ?? ?? ?? 3B CB }

condition:
		$a0 at entrypoint
}
	
	
rule PEProtector093CRYPToCRACk
{
strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PellesC300400450EXEX86CRTLIB
{
strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 ?? ?? ?? ?? 59 A3 }

condition:
		$a0
}
	
	
rule RLPackv118BasicaPLibAp0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 }

condition:
		$a0 at entrypoint
}
	
	
rule ARMProtector02SMoKE
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 09 20 40 00 EB 02 83 09 8D B5 9A 20 40 00 EB 02 83 09 BA 0B 12 00 00 EB 01 00 8D 8D A5 32 40 00 }

condition:
		$a0
}
	
	
rule vfpexeNcV500WangJianGuo
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner153Stubengine17GlOFF
{
strings:
		$a0 = { E8 33 FD FF FF 50 E8 0D 00 00 00 CC FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule CExev10a
{
strings:
		$a0 = { 55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall2628Jtit
{
strings:
		$a0 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXModifierv01x
{
strings:
		$a0 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1333ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
	$a1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B ?? 24 0C EB 01 ?? 83 ?? B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PureBasic4xNeilHodgson
{
strings:
		$a0 = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }

condition:
		$a0 at entrypoint
}
	
	
rule VxAugust16thIronMaiden
{
strings:
		$a0 = { BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02 }

condition:
		$a0 at entrypoint
}
	
	
rule SVKProtector13xEngPavolCerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E }

condition:
		$a0
}
	
	
rule SymantecCv400Libraries
{
strings:
		$a0 = { FA B8 ?? ?? DB E3 8E D8 8C 06 ?? ?? 8B D8 2B 1E ?? ?? 89 1E ?? ?? 26 }

condition:
		$a0 at entrypoint
}
	
	
rule ARJSFXCustom
{
strings:
		$a0 = { 60 BE 15 F0 40 00 8D BE EB 1F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
	$a1 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 18 C0 40 00 68 C4 A1 40 00 50 64 89 25 00 00 00 00 83 EC 60 53 56 57 89 65 E8 FF 15 38 03 41 00 A3 D0 D6 40 00 33 C0 A0 D1 D6 40 00 A3 DC D6 40 00 A1 D0 D6 }
	$a2 = { B8 ?? ?? ?? ?? 66 9C 60 50 8D 90 5C 01 00 00 68 00 00 40 00 83 3A 00 0F 84 C6 C1 FF FF 8B 04 24 8B 0A 0F BA F1 1F 73 13 FD 8B F0 8B F8 03 72 04 03 7A 08 F3 A5 83 C2 0C FC EB D9 83 C2 10 8B 5A }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule PEPACK099
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 80 BD E0 04 00 00 01 0F 84 F2 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMASM32
{
strings:
		$a0 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }

condition:
		$a0 at entrypoint
}
	
	
rule Freshbindv20gFresh
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1300ObsidiumSoftwareh
{
strings:
		$a0 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }

condition:
		$a0
}
	
	
rule FSG131dulekxt
{
strings:
		$a0 = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }

condition:
		$a0 at entrypoint
}
	
	
rule VxEddie2100
{
strings:
		$a0 = { E8 ?? ?? 4F 4F 0E E8 ?? ?? 47 47 1E FF ?? ?? CB E8 ?? ?? 84 C0 ?? ?? 50 53 56 57 1E 06 B4 51 CD 21 8E C3 ?? ?? ?? ?? ?? ?? ?? 8B F2 B4 2F CD 21 AC }

condition:
		$a0 at entrypoint
}
	
	
rule ScObfuscatorSuperCRackerSignbyfly
{
strings:
		$a0 = { 60 33 C9 8B 1D ?? ?? ?? ?? 03 1D ?? ?? ?? ?? 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D ?? ?? ?? ?? 75 E7 A1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 61 FF 25 ?? ?? ?? ?? 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualC60DLL
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 75 09 83 3D ?? ?? ?? ?? ?? EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 15 FF FF FF 85 C0 75 04 33 C0 EB 4E }

condition:
		$a0
}
	
	
rule VxInvoluntary1349
{
strings:
		$a0 = { BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB }

condition:
		$a0 at entrypoint
}
	
	
rule SCANAV
{
strings:
		$a0 = { 1E 0E 1F B8 ?? ?? 8E C0 26 8A 1E ?? ?? 80 ?? ?? 72 }

condition:
		$a0 at entrypoint
}
	
	
rule NETexecutableMicrosoft
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }

condition:
		$a0
}
	
	
rule MASMTASMsig1h
{
strings:
		$a0 = { CC FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }

condition:
		$a0
}
	
	
rule MSLRHv032afakePEBundle20x24xemadiciush
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 83 BD 9C 38 40 00 01 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv098
{
strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E }

condition:
		$a0 at entrypoint
}
	
	
rule AZProtect0001byAlexZakaAZCRC
{
strings:
		$a0 = { FC 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 8B C2 C1 C0 10 66 8B C1 C3 F0 DA 55 8B EC 53 56 33 C9 33 DB 8B 4D 0C 8B 55 10 8B 75 08 4E 4A 83 }
	$a1 = { EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 60 BE 00 ?? ?? 00 BF 00 00 40 00 EB 17 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 FF 25 ?? ?? ?? 00 8B C6 03 C7 8B F8 57 55 8B EC 05 7F 00 00 00 50 E8 E5 FF FF FF BA 8C ?? ?? 00 89 02 E9 1A 01 00 00 ?? 00 00 00 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 47 65 74 56 6F 6C 75 6D 65 49 6E 66 6F 72 6D 61 74 69 6F 6E 41 00 4D 65 73 73 61 67 65 42 6F 78 41 00 45 78 69 74 50 72 6F 63 65 73 73 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 }
	$a2 = { FC 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 8B C2 C1 C0 10 66 8B C1 C3 F0 DA 55 8B EC 53 56 33 C9 33 DB 8B 4D 0C 8B 55 10 8B 75 08 4E 4A 83 FB 08 72 05 33 DB 43 EB 01 43 33 C0 8A 04 31 8A 24 13 2A C4 88 04 31 E2 E6 5E 5B C9 C2 0C }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2
}
	
	
rule MEW510Northfox
{
strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule StonesPEEncryptorv20
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv096
{
strings:
		$a0 = { E9 59 E4 FF FF 00 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv095
{
strings:
		$a0 = { E9 D5 E4 FF FF 00 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacKV30LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin0b
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 26 E8 01 00 00 00 EA 5A 33 C9 }

condition:
		$a0
}
	
	
rule NsPack30byNorthStarLiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 55 F9 FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 7D F9 FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 11 F9 FF FF 89 95 }

condition:
		$a0 at entrypoint
}
	
	
rule SVKProtectorv132EngPavolCerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 0C 61 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 18 61 00 00 5D 6A FF FF 95 10 61 00 00 44 65 62 75 67 67 65 72 20 6F 72 20 74 6F 6F 6C 20 66 6F 72 20 6D 6F 6E 69 74 6F 72 69 6E 67 20 64 65 74 65 63 74 65 64 21 21 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSplitter12BillPrisonerTPOC
{
strings:
		$a0 = { E9 95 02 00 00 64 A1 00 00 00 00 83 38 FF 74 04 8B 00 EB F7 8B 40 04 C3 55 8B EC B8 00 00 00 00 8B 75 08 81 E6 00 00 FF FF B9 06 00 00 00 56 56 E8 B0 00 00 00 5E 83 F8 01 75 06 8B C6 C9 C2 04 00 81 EE 00 00 01 00 E2 E5 C9 C2 04 00 55 8B EC 8B 75 0C 8B DE 03 76 3C 8D 76 18 8D 76 60 8B 36 03 F3 56 8B 76 20 03 F3 33 D2 8B C6 8B 36 03 F3 8B 7D 08 B9 0E 00 00 00 FC F3 A6 0B C9 75 02 EB 08 }

condition:
		$a0
}
	
	
rule COPv10c1988
{
strings:
		$a0 = { BF ?? ?? BE ?? ?? B9 ?? ?? AC 32 ?? ?? ?? AA E2 ?? 8B ?? ?? ?? EB ?? 90 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv25RetailSlimLoaderBitsumTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

condition:
		$a0 at entrypoint
}
	
	
rule tElock098tHEEGOiSTEh
{
strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 }

condition:
		$a0
}
	
	
rule Morphinev27Holy_FatherRatter29A
{
strings:
		$a0 = { 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule Crunch40
{
strings:
		$a0 = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }

condition:
		$a0
}
	
	
rule PseudoSigner01REALBasicAnorganix
{
strings:
		$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv60SPx
{
strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }
	$a1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PPCPROTECT11XAlexeyGorchakov
{
strings:
		$a0 = { FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5 }

condition:
		$a0 at entrypoint
}
	
	
rule EnigmaProtector11X13XSukhovVladimirSergeNMarkin
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }

condition:
		$a0 at entrypoint
}
	
	
rule CipherWallSelfExtratorDecryptorGUI15
{
strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }

condition:
		$a0
}
	
	
rule ENIGMAProtectorV11CracKedByshooooflySukhovVladimir
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 C5 FA 81 }

condition:
		$a0 at entrypoint
}
	
	
rule PrivateexeProtectorV20SetiSoftTeamSignbyfly
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule iPBProtect013
{
strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 }

condition:
		$a0
}
	
	
rule PseudoSigner01ACProtect109
{
strings:
		$a0 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov190c
{
strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule ExcaliburV103forgotSignbyfly
{
strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeJoinerV10Yodaf2f
{
strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PCShrink071beta
{
strings:
		$a0 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2xxcompressedresourceswwwstrongbitcomSignByhaggar
{
strings:
		$a0 = { 56 57 53 31 DB 89 C6 89 D7 0F B6 06 89 C2 83 E0 1F C1 EA 05 74 2D 4A 74 15 8D 5C 13 02 46 C1 E0 08 89 FA 0F B6 0E 46 29 CA 4A 29 C2 EB 32 C1 E3 05 8D 5C 03 04 46 89 FA 0F B7 0E 29 CA 4A 83 C6 02 EB 1D C1 E3 04 46 89 C1 83 E1 0F 01 CB C1 E8 05 73 07 43 89 F2 01 DE EB 06 85 DB 74 0E EB A9 56 89 D6 89 D9 F3 A4 31 DB 5E EB 9D 89 F0 5B 5F 5E C3 }

condition:
		$a0
}
	
	
rule PseudoSigner02ZCode101
{
strings:
		$a0 = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv033v034BetaSignbyhot_UNP
{
strings:
		$a0 = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMASM32TASM32
{
strings:
		$a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
	$a1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB 02 F0 49 C1 F6 09 88 0B F7 DE 0F B6 F2 43 EB 02 CD 20 C1 E7 0A 48 EB 01 89 C1 E7 14 2B FF 3B C7 75 A8 E8 01 00 00 00 81 5F F7 D7 D9 EE 1F 5E 1E DD 1E 2E 5E 1E DC ?? ?? 5E 1E 71 06 28 1E 1E 1E 20 F0 93 23 A8 34 64 30 F0 E1 D0 9E 51 F9 C2 D1 20 1D 32 42 91 16 51 E7 1D 32 42 91 36 51 DE 1D 32 42 91 3F D1 20 5F CE 2E 1D 32 42 30 DE 91 17 93 5D C8 09 FA 06 61 1E 1E 1E 49 E9 93 2E 06 56 1E 1E 1E 09 46 CA EF 06 92 5F 31 E7 09 3A AF 66 DF FE 26 CA 06 40 1E 1E 1E 5B 1E 9B 1E 1E 91 28 9E 1A 23 91 24 A1 16 9D 95 20 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule BorlandPascalv70ProtectedMode
{
strings:
		$a0 = { B8 ?? ?? BB ?? ?? 8E D0 8B E3 8C D8 8E C0 0E 1F A1 ?? ?? 25 ?? ?? A3 ?? ?? E8 ?? ?? 83 3E ?? ?? ?? 75 }

condition:
		$a0 at entrypoint
}
	
	
rule UPX072
{
strings:
		$a0 = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack120BasicEditionaPLibAp0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SmartEMicrosoft
{
strings:
		$a0 = { EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06 }

condition:
		$a0 at entrypoint
}
	
	
rule MacromediaWindowsFlashProjectorPlayerv40
{
strings:
		$a0 = { 83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

condition:
		$a0 at entrypoint
}
	
	
rule SecuPackv15
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 ?? ?? ?? 6A 03 6A ?? 6A 01 ?? ?? ?? 80 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02UPX06
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPack32v100v111v112v120
{
strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 }

condition:
		$a0 at entrypoint
}
	
	
rule VProtectorV11vcasm
{
strings:
		$a0 = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MaskPE16yzkzero
{
strings:
		$a0 = { 36 81 2C 24 ?? ?? ?? 00 C3 60 }

condition:
		$a0
}
	
	
rule PseudoSigner01MEW11SE10Anorganix
{
strings:
		$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01ASPack2xxHeuristic
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV119aPlib043ap0xnbspnbspSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack037betaDwing
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule eXPressorv1501OptionsLightFullsupportCGSoftLabs
{
strings:
		$a0 = { 55 8B EC 81 EC ?? 02 00 00 53 56 57 83 A5 ?? FD FF FF 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv071DLL
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 }

condition:
		$a0 at entrypoint
}
	
	
rule TurboC1987orBorlandC1991
{
strings:
		$a0 = { FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV12ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 77 1E 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystem20RC2
{
strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

condition:
		$a0
}
	
	
rule PseudoSigner02BorlandCDLLMethod2
{
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule fEaRzCrypterv10fEaRz
{
strings:
		$a0 = { 55 8B EC B9 09 00 00 00 6A 00 6A 00 49 75 ?? 53 56 57 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 BA ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 85 DB 75 ?? 6A 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV119DllLZMA430ap0xSignbyfly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01PEProtect09Anorganix
{
strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeStealthWebToolMaster
{
strings:
		$a0 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F }

condition:
		$a0
}
	
	
rule AZProtect0x0001AlexZakaAZCRC
{
strings:
		$a0 = { EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtectorBasicProEdition112RandyLih
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 7B 03 00 00 03 C8 74 C4 75 C2 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E2 }

condition:
		$a0 at entrypoint
}
	
	
rule PEtitevxx
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 }

condition:
		$a0 at entrypoint
}
	
	
rule ACEArchive
{
strings:
		$a0 = { 2A 2A 41 43 45 2A 2A }

condition:
		$a0
}
	
	
rule ChSfxsmallv11
{
strings:
		$a0 = { BA ?? ?? E8 ?? ?? 8B EC 83 EC ?? 8C C8 BB ?? ?? B1 ?? D3 EB 03 C3 8E D8 05 ?? ?? 89 }

condition:
		$a0 at entrypoint
}
	
	
rule PrivateexeProtector215SetiSoftTeam
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXModifiedStubcFarbrauschConsumerConsulting
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 }
	$a1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2A 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 56 89 FE 29 C6 F3 A4 5E EB 9F 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 FF D3 11 C9 FF D3 72 F8 C3 31 C0 31 DB 31 C9 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F 0E 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 89 D8 E2 D9 8D BE ?? ?? ?? ?? 8B 07 09 C0 74 45 8B 5F 04 8D 84 30 ?? ?? ?? ?? 01 F3 50 83 C7 08 FF 96 ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 ?? ?? ?? ?? 61 E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MicrosoftVisualC70MFC
{
strings:
		$a0 = { 6A 60 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 94 00 00 00 8B C7 E8 ?? ?? ?? ?? 89 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv10801
{
strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
	$a1 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
	$a2 = { 90 90 75 ?? 90 E9 }
	$a3 = { 90 90 90 75 ?? 90 E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule ASPackv10802
{
strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }
	$a1 = { 90 90 75 01 90 E9 }
	$a2 = { 90 75 01 90 E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule ASPackv10803
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
	$a1 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }
	$a2 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }
	$a3 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule ProtectShareware11eCompservCMS
{
strings:
		$a0 = { 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 ?? 01 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 34 00 ?? 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 }

condition:
		$a0
}
	
	
rule FSGv110EngdulekxtMicrosoftVisualBasicMASM32
{
strings:
		$a0 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }

condition:
		$a0 at entrypoint
}
	
	
rule SLVc0deProtectorv11SLVh
{
strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
	$a1 = { E8 01 00 00 00 A0 5D EB 01 69 81 ED 5F 1A 40 00 8D 85 92 1A 40 00 F3 8D 95 83 1A 40 00 8B C0 8B D2 2B C2 83 E8 05 89 42 01 E8 FB FF FF FF 69 83 C4 08 E8 06 00 00 00 69 E8 F2 FF FF FF F3 B9 05 00 00 00 51 8D B5 BF 1A 40 00 8B FE B9 58 15 00 00 AC 32 C1 F6 D0 EB 01 00 D0 C0 FE C8 02 C1 AA E2 EF 59 E2 DE B7 FE AB E1 24 C8 0C 88 7A E1 B1 6A F7 95 83 1B A8 7F F8 A8 B0 1A 8B 08 91 47 6C 5A 88 6C 65 39 85 DB CB 54 3D B9 24 CF 4C AE C6 63 74 2C 63 F0 C8 18 0B 97 6B 79 63 A8 AB B8 78 A9 30 2F 2B DA 18 AC 35 45 36 BC 0D 7D 24 D1 51 3C E6 34 11 5A 43 06 24 89 FA 74 30 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule MSLRHv032afakePEBundle023xemadiciush
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule PESHiELD02
{
strings:
		$a0 = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv0896v102v105v122
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor239minimumprotectionwwwstrongbitcom
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? FF 50 C1 C8 18 89 05 ?? ?? ?? ?? C3 C1 C0 18 51 E9 ?? ?? ?? FF 84 C0 0F 84 6A F9 FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF E8 CF E9 FF FF B8 01 00 00 00 E9 ?? ?? ?? FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 ?? ?? ?? FF 84 C0 }

condition:
		$a0
}
	
	
rule Petite13
{
strings:
		$a0 = { 66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1 }

condition:
		$a0
}
	
	
rule EPack14litefinalby6aHguT
{
strings:
		$a0 = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }

condition:
		$a0 at entrypoint
}
	
	
rule PEArmorV0760V0765hying
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 }

condition:
		$a0 at entrypoint
}
	
	
rule tElock098tE
{
strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E ?? ?? 00 00 00 00 00 00 00 00 00 3E ?? ?? 00 2E ?? ?? 00 26 ?? ?? 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 36 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

condition:
		$a0 at entrypoint
}
	
	
rule UnnamedScrambler10p0ke
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 ?? ?? ?? ?? 40 00 E8 11 F4 FF FF BE 30 6B 40 00 33 C0 55 68 C9 42 40 00 64 FF 30 64 89 20 E8 C9 FA FF FF BA D8 42 40 00 8B ?? ?? ?? ?? FF FF 8B D8 B8 28 6B 40 00 8B 16 E8 37 F0 FF FF B8 2C 6B 40 00 8B 16 E8 2B F0 FF FF }
	$a1 = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 ?? ?? ?? ?? 40 00 E8 11 F4 FF FF BE 30 6B 40 00 33 C0 55 68 C9 42 40 00 64 FF 30 64 89 20 E8 C9 FA FF FF BA D8 42 40 00 8B ?? ?? ?? ?? FF FF 8B D8 B8 28 6B 40 00 8B 16 E8 37 F0 FF FF B8 2C 6B 40 00 8B 16 E8 2B F0 FF FF B8 28 6B 40 00 E8 19 F0 FF FF 8B D0 8B C3 8B 0E E8 42 E3 FF FF BA DC 42 40 00 8B C6 E8 2A FA FF FF 8B D8 B8 20 6B 40 00 8B 16 E8 FC EF FF FF B8 24 6B 40 00 8B 16 E8 F0 EF FF FF B8 20 6B 40 00 E8 DE EF FF FF 8B D0 8B C3 8B 0E E8 07 E3 FF FF 6A 00 6A 19 6A 00 6A 32 A1 28 6B 40 00 E8 59 EF FF FF 83 E8 05 03 C0 8D 55 EC E8 94 FE FF FF 8B 55 EC B9 24 6B 40 00 A1 20 6B 40 00 E8 E2 F6 FF FF 6A 00 6A 19 6A 00 6A 32 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule WARNINGTROJANADinjector
{
strings:
		$a0 = { 90 61 BE 00 20 44 00 8D BE 00 F0 FB FF C7 87 9C E0 04 00 6A F0 8A 5E 57 83 CD FF EB 0E }

condition:
		$a0 at entrypoint
}
	
	
rule TopSpeedv3011989
{
strings:
		$a0 = { 1E BA ?? ?? 8E DA 8B ?? ?? ?? 8B ?? ?? ?? FF ?? ?? ?? 50 53 }

condition:
		$a0 at entrypoint
}
	
	
rule CodeCryptv0164
{
strings:
		$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }

condition:
		$a0 at entrypoint
}
	
	
rule LCCWin32v1x
{
strings:
		$a0 = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }

condition:
		$a0 at entrypoint
}
	
	
rule PeX099EngbartCrackPl
{
strings:
		$a0 = { E9 F5 00 00 00 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

condition:
		$a0
}
	
	
rule PDSgraphicsfileformat
{
strings:
		$a0 = { 49 4D 41 47 45 49 44 45 4E 54 49 46 49 45 52 20 }

condition:
		$a0
}
	
	
rule RECv0343
{
strings:
		$a0 = { 06 1E B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01ASProtectAnorganix
{
strings:
		$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PocketPCARM
{
strings:
		$a0 = { F0 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 ?? 00 00 EB 07 30 A0 E1 06 20 A0 E1 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB F0 40 BD E8 ?? 00 00 EA ?? 40 2D E9 }
	$a1 = { F0 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 ?? 00 00 EB 07 30 A0 E1 06 20 A0 E1 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB F0 40 BD E8 ?? 00 00 EA ?? 40 2D E9 ?? ?? 9F E5 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 9F E5 00 ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule AnskyaBinderv11Anskya
{
strings:
		$a0 = { BE ?? ?? ?? 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack23LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD }

condition:
		$a0
}
	
	
rule VProtectorV10Bvcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

condition:
		$a0 at entrypoint
}
	
	
rule SecurePE1Xwwwdeepzoneorg
{
strings:
		$a0 = { 8B 04 24 E8 00 00 00 00 5D 81 ED 4C 2F 40 00 89 85 61 2F 40 00 8D 9D 65 2F 40 00 53 C3 00 00 00 00 8D B5 BA 2F 40 00 8B FE BB 65 2F 40 00 B9 C6 01 00 00 AD 2B C3 C1 C0 03 33 C3 AB 43 81 FB 8E 2F 40 00 75 05 BB 65 2F 40 00 E2 E7 89 AD 1A 31 40 00 89 AD 55 34 40 00 89 AD 68 34 40 00 8D 85 BA 2F 40 00 50 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakePECrypt102emadiciush
{
strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePEBundle20x24xemadicius
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 83 BD 9C 38 40 00 01 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 }

condition:
		$a0
}
	
	
rule MSLRHv031a
{
strings:
		$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F }
	$a1 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F CA C0 C7 91 0F CB C1 D9 0C 86 F9 86 D7 D1 D9 EB 01 A5 EB 01 11 EB 01 1D 0F C1 C2 0F CB 0F C1 C2 EB 01 A1 C0 E9 FD 0F C1 D1 EB 01 E3 0F CA 87 D9 EB 01 F3 0F CB 87 C2 0F C0 F9 D0 F7 EB 01 2F 0F C9 C0 DC C4 EB 01 35 0F CA D3 D1 86 C8 EB 01 01 0F C0 F5 87 C8 D0 DE EB 01 95 EB 01 E1 EB 01 FD EB 01 EC 87 D3 0F CB C1 DB 35 D3 E2 0F C8 86 E2 86 EC C1 FB 12 D2 EE 0F C9 D2 F6 0F CA 87 C3 C1 D3 B3 EB 01 BF D1 CB 87 C9 0F CA 0F C1 DB EB 01 44 C0 CA F2 0F C1 D1 0F CB EB 01 D3 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }

condition:
		$a0 or $a1
}
	
	
rule MicrosoftVisualC5071
{
strings:
		$a0 = { 55 8B EC 81 EC 04 01 00 00 68 04 01 00 00 8D 85 FC FE FF FF 50 6A 00 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D FC FE FF FF 51 E8 ?? ?? ?? ?? 83 C4 04 E8 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 8B E5 5D C2 10 00 }

condition:
		$a0
}
	
	
rule SoftDefenderv11xRandyLi
{
strings:
		$a0 = { 74 07 75 05 ?? ?? ?? ?? ?? 74 1F 75 1D ?? 68 ?? ?? ?? 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 ?? ?? ?? E8 F4 FF FF FF ?? ?? ?? 78 0F 79 0D }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePackV11XMethod1bagieSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD ?? ?? ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall2628Jtith
{
strings:
		$a0 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 }

condition:
		$a0 at entrypoint
}
	
	
rule vprotector12vcasm
{
strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 }

condition:
		$a0
}
	
	
rule FakeNinjav28Spirit
{
strings:
		$a0 = { BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 }

condition:
		$a0
}
	
	
rule PECompactv133
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 00 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E }

condition:
		$a0 at entrypoint
}
	
	
rule DragonArmorOrient
{
strings:
		$a0 = { BF 4C ?? ?? 00 83 C9 FF 33 C0 68 34 ?? ?? 00 F2 AE F7 D1 49 51 68 4C ?? ?? 00 E8 11 0A 00 00 83 C4 0C 68 4C ?? ?? 00 FF 15 00 ?? ?? 00 8B F0 BF 4C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 4C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 }
	$a1 = { BF 4C ?? ?? 00 83 C9 FF 33 C0 68 34 ?? ?? 00 F2 AE F7 D1 49 51 68 4C ?? ?? 00 E8 11 0A 00 00 83 C4 0C 68 4C ?? ?? 00 FF 15 00 ?? ?? 00 8B F0 BF 4C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 4C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 5C ?? ?? 00 E8 C0 09 00 00 8B 1D 04 ?? ?? 00 83 C4 0C 68 5C ?? ?? 00 56 FF D3 A3 D4 ?? ?? 00 BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 5C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Upack024betaDwing
{
strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 }

condition:
		$a0 at entrypoint
}
	
	
rule JExeCompressorV10UsAr
{
strings:
		$a0 = { 0F C8 0F CF C6 C4 8B 0F AC EA 99 0F AD D8 13 F5 0F BD EF 85 EF 85 DA 69 FE ?? ?? ?? ?? 21 F9 BE ?? ?? ?? ?? 23 CF 0F BC FE D2 DC 85 EF B9 ?? ?? ?? ?? C6 C0 F7 8D 35 ?? ?? ?? ?? 8D 0D }

condition:
		$a0 at entrypoint
}
	
	
rule FreePascal09910
{
strings:
		$a0 = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }

condition:
		$a0
}
	
	
rule eXPressor1451CGSoftLabsh
{
strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? ?? 05 00 ?? ?? ?? A3 08 ?? ?? ?? A1 08 ?? ?? ?? B9 81 ?? ?? ?? 2B 48 18 89 0D 0C ?? ?? ?? 83 3D 10 ?? ?? ?? 00 74 16 A1 08 ?? ?? ?? 8B 0D 0C ?? ?? ?? 03 48 14 }

condition:
		$a0
}
	
	
rule RCryptorV16cVaskaSignbyfly
{
strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtectorV1031AshkbizDanehkarSignbyfly
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 74 72 42 00 8B D5 81 C2 C3 72 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3F A9 42 00 81 E9 6E 73 42 00 8B D5 81 C2 6E 73 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 98 2E 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftBasicCompilerv560198297
{
strings:
		$a0 = { 9A ?? ?? ?? ?? 9A ?? ?? ?? ?? 9A ?? ?? ?? ?? 33 DB BA ?? ?? 9A ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 33 DB }

condition:
		$a0 at entrypoint
}
	
	
rule PellesC2x4xDLLPelleOrinius
{
strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }

condition:
		$a0 at entrypoint
}
	
	
rule Morphinev33SilentSoftwareSilentShieldc2005h
{
strings:
		$a0 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }

condition:
		$a0
}
	
	
rule VirogensPEShrinkerv014
{
strings:
		$a0 = { 9C 55 E8 ?? ?? ?? ?? 87 D5 5D 60 87 D5 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 57 56 AD 0B C0 74 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorv15xCGSoftLabsh
{
strings:
		$a0 = { 55 8B EC 81 EC 58 02 00 00 53 56 57 83 A5 CC FD FF FF 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C 01 75 23 }

condition:
		$a0 at entrypoint
}
	
	
rule Can2Exev001
{
strings:
		$a0 = { 0E 1F 0E 07 E8 ?? ?? E8 ?? ?? 3A C6 73 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01ACProtect109Anorganix
{
strings:
		$a0 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 90 90 90 EB 06 00 00 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule TrainerCreationKit5Trainer
{
strings:
		$a0 = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 }

condition:
		$a0
}
	
	
rule Apex30alpha500mhz
{
strings:
		$a0 = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 ?? ?? 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 ?? ?? ?? 00 C3 }

condition:
		$a0
}
	
	
rule SimbiOZPoly21Extranger
{
strings:
		$a0 = { 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90 }

condition:
		$a0 at entrypoint
}
	
	
rule PSAdobeFontv10
{
strings:
		$a0 = { 80 01 ?? ?? 00 00 25 21 50 53 2D 41 64 6F 62 65 46 6F 6E 74 2D 31 2E 30 3A }

condition:
		$a0
}
	
	
rule Armadillov184
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov183
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 64 84 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov182
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 74 81 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov180
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinv01Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF }

condition:
		$a0 at entrypoint
}
	
	
rule LibrariesbyJohnSocha
{
strings:
		$a0 = { BB ?? ?? 8E DB 2E 89 ?? ?? ?? 8D ?? ?? ?? 25 ?? ?? FA 8E D3 8B E0 FB 26 A1 A3 ?? ?? B4 30 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandCforWin161991
{
strings:
		$a0 = { 9A FF FF 00 00 0B C0 75 ?? E9 ?? ?? 8C ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? B8 FF FF 50 9A FF FF 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RJoiner12aVaska
{
strings:
		$a0 = { 55 8B EC 81 EC 0C 01 00 00 8D 85 F4 FE FF FF 56 50 68 04 01 00 00 FF 15 0C 10 40 00 94 90 94 8D 85 F4 FE FF FF 50 FF 15 08 10 40 00 94 90 94 BE 00 20 40 00 94 90 94 83 3E FF 74 7D 53 57 33 DB 8D 7E 04 94 90 94 53 68 80 00 00 00 6A 02 53 6A 01 68 00 00 00 }
	$a1 = { 55 8B EC 81 EC 0C 01 00 00 8D 85 F4 FE FF FF 56 50 68 04 01 00 00 FF 15 0C 10 40 00 94 90 94 8D 85 F4 FE FF FF 50 FF 15 08 10 40 00 94 90 94 BE 00 20 40 00 94 90 94 83 3E FF 74 7D 53 57 33 DB 8D 7E 04 94 90 94 53 68 80 00 00 00 6A 02 53 6A 01 68 00 00 00 C0 57 FF 15 04 10 40 00 89 45 F8 94 90 94 8B 06 8D 74 06 04 94 90 94 8D 45 FC 53 50 8D 46 04 FF 36 50 FF 75 F8 FF 15 00 10 40 00 94 90 94 FF 75 F8 FF 15 10 10 40 00 94 90 94 8D 85 F4 FE FF FF 6A 0A 50 53 57 68 20 10 40 00 53 FF 15 18 10 40 00 94 90 94 8B 06 8D 74 06 04 94 90 94 83 3E FF 75 89 5F 5B 33 C0 5E C9 C2 10 00 CC CC 24 11 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RLPackV119DllaPlib043ap0xSignbyfly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 89 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 }

condition:
		$a0 at entrypoint
}
	
	
rule EncryptPE12003518WFS
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv168v184
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 7B 11 }

condition:
		$a0 at entrypoint
}
	
	
rule TXT2COMReadAMaticv10
{
strings:
		$a0 = { B8 ?? ?? 8E D8 8C 06 ?? ?? FA 8E D0 BC ?? ?? FB B4 ?? CD 21 A3 ?? ?? 06 50 B4 34 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv071v072
{
strings:
		$a0 = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }

condition:
		$a0 at entrypoint
}
	
	
rule PEQuakev006forgotush
{
strings:
		$a0 = { E8 A5 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D ?? ?? ?? 2D ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 5D 81 ED 05 00 00 00 8D 75 3D 56 FF 55 31 8D B5 81 00 00 00 56 50 FF 55 2D 89 85 8E 00 00 00 6A 04 68 00 10 00 00 68 ?? ?? 00 00 6A 00 FF 95 8E 00 00 00 50 8B 9D 7D 00 00 00 03 DD 50 53 E8 04 00 00 00 5A 55 FF E2 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtectorProEdition116RandyLi
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 }

condition:
		$a0
}
	
	
rule Packman0001Bubbasofth
{
strings:
		$a0 = { 0F 85 ?? FF FF FF 8D B3 ?? ?? ?? ?? EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00 00 ?? ?? B8 00 ?? ?? 00 0B C0 74 34 03 C3 EB 2A 8D 70 08 03 40 04 33 ED 33 D2 66 8B 2E 66 0F A4 EA 04 80 FA 03 75 0D 81 E5 FF 0F 00 00 03 EF 03 EB 01 4D 00 46 46 3B F0 75 DC 8B 38 85 FF 75 D0 61 E9 ?? FE FF FF 02 D2 75 05 8A 16 46 12 D2 C3 }

condition:
		$a0
}
	
	
rule Reg2Exe222223byJanVorel
{
strings:
		$a0 = { 6A 00 E8 2F 1E 00 00 A3 C4 35 40 00 E8 2B 1E 00 00 6A 0A 50 6A 00 FF 35 C4 35 40 00 E8 07 00 00 00 50 E8 1B 1E 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 C8 35 40 00 E8 76 16 00 00 83 C4 0C 8B 44 24 04 A3 CC 35 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 }
	$a1 = { 6A 00 E8 2F 1E 00 00 A3 C4 35 40 00 E8 2B 1E 00 00 6A 0A 50 6A 00 FF 35 C4 35 40 00 E8 07 00 00 00 50 E8 1B 1E 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 C8 35 40 00 E8 76 16 00 00 83 C4 0C 8B 44 24 04 A3 CC 35 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 EC 1D 00 00 A3 C8 35 40 00 E8 62 1D 00 00 E8 92 1A 00 00 E8 80 16 00 00 E8 13 14 00 00 68 01 00 00 00 68 08 36 40 00 68 00 00 00 00 8B 15 08 36 40 00 E8 71 3F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 3F 00 00 FF 35 48 31 40 00 B8 00 01 00 00 E8 0D 13 00 00 8D 0D EC 35 40 00 5A E8 F2 13 00 00 68 00 01 00 00 FF 35 EC 35 40 00 E8 84 1D 00 00 A3 F4 35 40 00 FF 35 48 31 40 00 FF 35 F4 35 40 00 FF 35 EC 35 40 00 E8 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule FSG110EngdulekxtBorlandC
{
strings:
		$a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv120EngdulekxtBorlandDelphiMicrosoftVisualC
{
strings:
		$a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 F7 2B FE EB 01 7F 81 EF DF 30 90 1E EB 02 CD 20 87 FA 88 10 80 EA 03 40 EB 01 20 4E EB 01 3D 83 FE 00 75 A2 EB 02 CD 20 EB 01 C3 78 73 42 F7 35 6C 2D 3F ED 33 97 ?? ?? ?? 5D F0 45 29 55 57 55 71 63 02 72 E9 1F 2D 67 B1 C0 91 FD 10 58 A3 90 71 6C 83 11 E0 5D 20 AE 5C 71 83 D0 7B 10 97 54 17 11 C0 0E 00 33 76 85 33 3C 33 21 31 F5 50 CE 56 6C 89 C8 F7 CD 70 D5 E3 DD 08 E8 4E 25 FF 0D F3 ED EF C8 0B 89 A6 CD 77 42 F0 A6 C8 19 66 3D B2 CD E7 89 CB 13 D7 D5 E3 1E DF 5A E3 D5 50 DF B3 39 32 C0 2D B0 3F B4 B4 43 }

condition:
		$a0 at entrypoint
}
	
	
rule CrunchPE
{
strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 }

condition:
		$a0 at entrypoint
}
	
	
rule EPExEPackV106aHguTgluk
{
strings:
		$a0 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }

condition:
		$a0 at entrypoint
}
	
	
rule yzpackV11UsArSignbyfly
{
strings:
		$a0 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 8D 40 7C 8B 40 3C 89 45 04 E8 F3 07 00 00 60 8B 5D 04 8B 73 3C 8B 74 33 78 03 F3 56 8B 76 20 03 F3 33 C9 49 92 41 AD 03 C3 52 33 FF 0F B6 10 38 F2 }

condition:
		$a0 at entrypoint
}
	
	
rule RosAsm2050aBetov
{
strings:
		$a0 = { 55 8B EC 60 8B 5D 08 B9 08 00 00 00 BF ?? ?? ?? ?? 83 C7 07 FD 8A C3 24 0F 04 30 3C 39 76 02 04 07 AA C1 EB 04 E2 EE FC 68 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 61 8B E5 5D C2 04 00 }

condition:
		$a0
}
	
	
rule shoooosPackshoooo
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 ?? ?? ?? ?? E8 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01MicrosoftVisualC620
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 55 8B EC 83 EC 50 53 56 57 BE 90 90 90 90 8D 7D F4 A5 A5 66 A5 8B }

condition:
		$a0 at entrypoint
}
	
	
rule PCGuardv303dv305d
{
strings:
		$a0 = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackFullEdition117iBoxLZMA
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 67 30 00 00 8D 9D 66 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A }

condition:
		$a0 at entrypoint
}
	
	
rule CICompressv10
{
strings:
		$a0 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 35 F8 10 40 00 FF 15 34 10 40 00 FF 35 F8 10 40 00 FF 15 30 10 40 00 68 00 40 00 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 15 3C 10 40 00 6A 00 FF 15 28 10 40 00 60 33 DB 33 C9 E8 7F 00 00 00 73 0A B1 08 E8 82 00 00 00 AA EB EF E8 6E 00 00 00 73 14 B1 04 E8 71 00 00 00 3C 00 74 EB 56 8B F7 2B F0 A4 5E EB D4 33 ED E8 51 00 00 00 72 10 B1 02 E8 54 00 00 00 3C 00 74 3B 8B E8 C1 C5 08 B1 08 E8 44 00 00 00 0B C5 50 33 ED E8 2E 00 00 00 72 0C B1 02 E8 31 00 00 00 8B E8 C1 C5 08 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeShieldv27b
{
strings:
		$a0 = { EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40 00 03 9D E6 90 40 00 53 8B C3 8B FB 2D AC 90 40 00 89 85 AD 90 40 00 8D B5 AC 90 40 00 B9 40 04 00 00 F3 A5 8B FB C3 BD 00 00 00 00 8B F7 83 C6 54 81 C7 FF 10 00 00 56 57 57 56 FF 95 DA 90 40 00 8B C8 5E 5F 8B C1 C1 F9 02 F3 A5 03 C8 83 E1 03 F3 A4 EB 26 D0 12 5B 00 AC 12 5B 00 48 12 5B 00 00 00 40 00 00 D0 5A 00 00 10 5B 00 87 DB 87 DB 87 DB 87 DB 87 DB 87 DB 87 DB 8B 0E B5 E6 90 40 07 56 03 76 EE 0F 18 83 C6 14 12 35 97 80 8D BD 63 39 0D B9 06 86 02 07 F3 A5 6A 04 68 06 10 12 1B FF B5 51 29 EE 10 22 95 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftAccessDatabasefile
{
strings:
		$a0 = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 00 }

condition:
		$a0
}
	
	
rule AntiDotev14osCESingbyosCCoDeR
{
strings:
		$a0 = { 68 95 01 00 00 E8 D0 FD FF FF 68 95 01 00 00 E8 C3 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITEv114v120
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 20 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeToolsCOM2EXE
{
strings:
		$a0 = { E8 ?? ?? 5D 83 ED ?? 8C DA 2E 89 96 ?? ?? 83 C2 ?? 8E DA 8E C2 2E 01 96 ?? ?? 60 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV2547V2600JititSignbyfly
{
strings:
		$a0 = { E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 ?? ?? ?? ?? 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxARCV4
{
strings:
		$a0 = { E8 00 00 5D 81 ED 06 01 81 FC 4F 50 74 0B 8D B6 86 01 BF 00 01 57 A4 EB 11 1E 06 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo3X5XSiliconRealmsToolworks
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 }
	$a1 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 60 33 C9 75 02 EB 15 EB 33 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ThinstallEmbeddedV2422V2428JititSignbyfly
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D 9B 1A 00 00 B9 84 1A 00 00 BA 14 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD E0 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov252beta2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv122
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualC80MFC
{
strings:
		$a0 = { 48 83 EC 28 E8 ?? ?? 00 00 48 83 C4 28 E9 0E FD FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC }
	$a1 = { C0 ?? ?? 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 00 00 ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 ?? 00 00 00 00 00 ?? ?? ?? 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PCShrinkerv029
{
strings:
		$a0 = { BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacKV33LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 00 74 }

condition:
		$a0 at entrypoint
}
	
	
rule CopyMinderMicrocosmLtd
{
strings:
		$a0 = { 83 25 ?? ?? ?? ?? EF 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 }

condition:
		$a0 at entrypoint
}
	
	
rule Crunchv5BitArts
{
strings:
		$a0 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00 00 8B 56 3C 8D 8C 32 C8 00 00 00 83 39 00 74 50 8B D9 53 68 BB D4 C3 79 33 C0 50 E8 0E 04 00 00 50 8D 95 EC 07 00 00 52 6A 04 68 00 10 00 00 FF B5 E8 07 00 00 FF D0 58 5B C7 03 00 00 00 00 C7 43 04 00 00 00 00 8D 95 F0 07 00 00 52 FF B5 EC 07 00 00 68 00 10 00 00 FF B5 E8 07 00 00 FF D0 68 6C D9 B2 96 33 C0 50 E8 C1 03 00 00 89 85 ?? 46 00 00 68 EC 49 7B 79 33 C0 50 E8 AE 03 00 00 89 85 ?? 46 00 00 E8 04 06 00 00 E9 F3 05 00 00 51 52 53 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 }

condition:
		$a0 at entrypoint
}
	
	
rule PCShrinkerv020
{
strings:
		$a0 = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo500SiliconRealmsToolworks
{
strings:
		$a0 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 }
	$a1 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 48 11 00 00 59 89 7D FC FF 75 08 E8 01 49 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 66 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 AF F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 EE 0F 00 00 59 C3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule UPXLockv10CyberDoom
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 60 E8 2B 03 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PrincessSandy10eMiNENCEProcessPatcherPatch
{
strings:
		$a0 = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 }

condition:
		$a0
}
	
	
rule SLVc0deProtector060SLVICU
{
strings:
		$a0 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD }

condition:
		$a0
}
	
	
rule Kryptonv03
{
strings:
		$a0 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }

condition:
		$a0 at entrypoint
}
	
	
	
rule Kryptonv05
{
strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }

condition:
		$a0 at entrypoint
}
	
	
rule Kryptonv04
{
strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }

condition:
		$a0 at entrypoint
}
	
	
rule NoNamePacker
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 2E 34 46 00 B9 55 4A 46 00 81 E9 26 37 46 00 89 EA 81 C2 26 37 46 00 8D 3A 89 FE 31 C0 E9 D3 02 00 00 CC CC CC CC E9 CA 02 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 6F 66 74 57 61 72 65 50 72 6F 74 65 63 74 6F 72 5C }

condition:
		$a0 at entrypoint
}
	
	
rule PassLock2000v10EngMoonlightSoftware
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 }
	$a1 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24 2C 01 00 00 00 74 05 0F B7 44 24 30 83 C4 44 89 43 56 FF 15 D0 61 40 00 E8 9E 00 00 00 89 43 4C FF 15 D4 61 40 00 89 43 48 6A 00 FF 15 E4 61 40 00 89 43 5C E8 F9 00 00 00 E8 AA 00 00 00 B8 FF 00 00 00 72 0D 53 E8 96 00 00 00 5B FF 4B 10 FF 4B 18 5F 5E 5B 5D 50 FF 15 C8 61 40 00 C3 83 7D 0C 01 75 3F E8 81 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 FF 15 D0 61 40 00 E8 3A 00 00 00 89 43 4C FF 15 D4 61 40 00 89 43 48 8B 45 08 89 43 5C E8 9A 00 00 00 E8 4B 00 00 00 72 11 66 FF 43 5A 8B 45 0C 89 43 60 53 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule SafeDisc4
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }

condition:
		$a0
}
	
	
rule AlexProtector10beta2byAlex
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25 }
	$a1 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 EB 01 E9 FF FF 60 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 0F 31 8B D8 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 8B CA EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 0F 31 2B C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 1B D1 0F 31 03 C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 13 D1 0F 31 2B C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 EB 05 68 F0 0F C7 C8 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 1B D1 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 85 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule MoleBoxv254Teggo
{
strings:
		$a0 = { 00 8B 4D F0 8B 11 89 15 ?? ?? ?? 00 8B 45 FC A3 ?? ?? ?? 00 5F 5E 8B E5 5D C3 CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 24 61 58 58 FF D0 E8 ?? ?? 00 00 6A 00 FF 15 ?? ?? ?? 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

condition:
		$a0
}
	
	
rule Pe1232006412
{
strings:
		$a0 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B }

condition:
		$a0
}
	
	
rule InstallShield2000
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 }

condition:
		$a0 at entrypoint
}
	
	
rule TheNortonAntivirusInformationfile
{
strings:
		$a0 = { 54 68 65 20 4E 6F 72 74 6F 6E 20 41 6E 74 69 56 69 72 75 73 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 46 69 6C 65 }

condition:
		$a0
}
	
	
rule MSLRH032afakeBJFNT13emadicius
{
strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 }

condition:
		$a0
}
	
	
rule CrunchV50Bitarts
{
strings:
		$a0 = { EB 15 03 00 00 00 06 }

condition:
		$a0 at entrypoint
}
	
	
rule PowerBASICCC30x
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXHiT001sibaway7yahoocom
{
strings:
		$a0 = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule Obsidium1337ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV1337ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 }

condition:
		$a0 at entrypoint
}
	
	
rule PerlApp602ActiveState
{
strings:
		$a0 = { 68 2C EA 40 00 FF D3 83 C4 0C 85 C0 0F 85 CD 00 00 00 6A 09 57 68 20 EA 40 00 FF D3 83 C4 0C 85 C0 75 12 8D 47 09 50 FF 15 1C D1 40 00 59 A3 B8 07 41 00 EB 55 6A 08 57 68 14 EA 40 00 FF D3 83 C4 0C 85 C0 75 11 8D 47 08 50 FF 15 1C D1 40 00 59 89 44 24 10 EB 33 6A 09 57 68 08 EA 40 00 FF D3 83 C4 0C 85 C0 74 22 6A 08 57 68 FC E9 40 00 FF D3 83 C4 0C 85 C0 74 11 6A 0B 57 68 F0 E9 40 00 FF D3 83 C4 0C 85 C0 75 55 }
	$a1 = { 68 9C E1 40 00 FF 15 A4 D0 40 00 85 C0 59 74 0F 50 FF 15 1C D1 40 00 85 C0 59 89 45 FC 75 62 6A 00 8D 45 F8 FF 75 0C F6 45 14 01 50 8D 45 14 50 E8 9B 01 00 00 83 C4 10 85 C0 0F 84 E9 00 00 00 8B 45 F8 83 C0 14 50 FF D6 85 C0 59 89 45 FC 75 0E FF 75 14 FF 15 78 D0 40 00 E9 C9 00 00 00 68 8C E1 40 00 FF 75 14 50 }

condition:
		$a0 or $a1
}
	
	
rule VxVCL
{
strings:
		$a0 = { AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89 }

condition:
		$a0 at entrypoint
}
	
	
rule VterminalV10XLeiPeng
{
strings:
		$a0 = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SVKProtector132EngPavolCerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E }

condition:
		$a0
}
	
	
rule PEcryptbyarchphase
{
strings:
		$a0 = { 55 8B EC 83 C4 E0 53 56 33 C0 89 45 E4 89 45 E0 89 45 EC ?? ?? ?? ?? 64 82 40 00 E8 7C C7 FF FF 33 C0 55 68 BE 84 40 00 64 FF 30 64 89 20 68 CC 84 40 00 ?? ?? ?? ?? 00 A1 10 A7 40 00 50 E8 1D C8 FF FF 8B D8 85 DB 75 39 E8 3A C8 FF FF 6A 00 6A 00 68 A0 A9 }
	$a1 = { 55 8B EC 83 C4 E0 53 56 33 C0 89 45 E4 89 45 E0 89 45 EC ?? ?? ?? ?? 64 82 40 00 E8 7C C7 FF FF 33 C0 55 68 BE 84 40 00 64 FF 30 64 89 20 68 CC 84 40 00 ?? ?? ?? ?? 00 A1 10 A7 40 00 50 E8 1D C8 FF FF 8B D8 85 DB 75 39 E8 3A C8 FF FF 6A 00 6A 00 68 A0 A9 40 00 68 00 04 00 00 50 6A 00 68 00 13 00 00 E8 FF C7 FF FF 6A 00 68 E0 84 40 00 A1 A0 A9 40 00 50 6A 00 E8 ?? ?? ?? ?? E9 7D 01 00 00 53 A1 10 A7 40 00 50 E8 42 C8 FF FF 8B F0 85 F6 75 18 6A 00 68 E0 84 40 00 68 E4 84 40 00 6A 00 E8 71 C8 FF FF E9 53 01 00 00 53 6A 00 E8 2C C8 FF FF A3 ?? ?? ?? ?? 83 3D 48 A8 40 00 00 75 18 6A 00 68 E0 84 40 00 68 F8 84 40 00 6A 00 E8 43 C8 FF FF E9 25 01 00 00 56 E8 F8 C7 FF FF A3 4C A8 40 00 A1 48 A8 40 00 E8 91 A1 FF FF 8B D8 8B 15 48 A8 40 00 85 D2 7C 16 42 33 C0 8B 0D 4C A8 40 00 03 C8 8A 09 8D 34 18 88 0E 40 4A 75 ED 8B 15 48 A8 40 00 85 D2 7C 32 42 33 C0 8D 34 18 8A 0E 80 F9 01 75 05 C6 06 FF EB 1C 8D 0C 18 8A 09 84 ?? ?? ?? ?? ?? 00 EB 0E 8B 0D 4C A8 40 00 03 C8 0F B6 09 49 88 0E 40 4A 75 D1 8D ?? ?? ?? ?? E8 A5 A3 FF FF 8B 45 E8 8D 55 EC E8 56 D5 FF FF 8D 45 EC BA 18 85 40 00 E8 79 BA FF FF 8B 45 EC E8 39 BB FF FF 8B D0 B8 54 A8 40 00 E8 31 A6 FF FF BA 01 00 00 00 B8 54 A8 40 00 E8 12 A9 FF FF E8 DD A1 FF FF 68 50 A8 40 00 8B D3 8B 0D 48 A8 40 00 B8 54 A8 40 00 E8 56 A7 FF FF E8 C1 A1 FF FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MinGW32xWinMain
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D }

condition:
		$a0
}
	
	
rule PEEncrypt10Liwuyue
{
strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D 0F 05 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 }

condition:
		$a0 at entrypoint
}
	
	
rule ActiveMARK5xTrymediaSystemsInch
{
strings:
		$a0 = { 20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67 }
	$a1 = { 20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67 67 65 72 20 69 6E 20 6D 65 6D 6F 72 79 2E 0D 0A 50 6C 65 61 73 65 20 75 6E 6C 6F 61 64 20 74 68 65 20 64 65 62 75 67 67 65 72 20 61 6E 64 20 72 65 73 74 61 72 74 20 74 68 65 20 61 70 70 6C 69 63 61 74 69 6F 6E 2E 00 57 61 72 6E 69 6E 67 }

condition:
		$a0 or $a1
}
	
	
rule StonyBrookPascalv614
{
strings:
		$a0 = { 31 ED 9A ?? ?? ?? ?? 55 89 E5 ?? EC ?? ?? 9A }

condition:
		$a0 at entrypoint
}
	
	
rule InstallAnywhere61ZeroGSoftwareInc
{
strings:
		$a0 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }
	$a1 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
	$a2 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule iLUCRYPTv4018exe
{
strings:
		$a0 = { 8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81 }

condition:
		$a0 at entrypoint
}
	
	
rule EncryptPEV22006710WFS
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 }

condition:
		$a0
}
	
	
rule StonesPEEncryptorv10
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36 }

condition:
		$a0 at entrypoint
}
	
	
rule PolyBoxDAnskya
{
strings:
		$a0 = { 55 8B EC 33 C9 51 51 51 51 51 53 33 C0 55 68 84 2C 40 00 64 FF 30 64 89 20 C6 45 FF 00 B8 B8 46 40 00 BA 24 00 00 00 E8 8C F3 FF FF 6A 24 BA B8 46 40 00 8B 0D B0 46 40 00 A1 94 46 40 00 E8 71 FB FF FF 84 C0 0F 84 6E 01 00 00 8B 1D D0 46 40 00 8B C3 83 C0 24 03 05 D8 46 40 00 3B 05 B4 46 40 00 0F 85 51 01 00 00 8D 45 F4 BA B8 46 40 00 B9 10 00 00 00 E8 A2 EC FF FF 8B 45 F4 BA 9C 2C 40 00 E8 F1 ED FF FF }

condition:
		$a0
}
	
	
rule Mew10execoder10NorthfoxHCC
{
strings:
		$a0 = { 33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70 }

condition:
		$a0 at entrypoint
}
	
	
rule PECrypt102
{
strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 }

condition:
		$a0 at entrypoint
}
	
	
rule CorelDraw8CDRGraphicsformat
{
strings:
		$a0 = { 52 49 46 46 ?? ?? ?? ?? 43 44 52 38 }

condition:
		$a0
}
	
	
rule LatticeCv101
{
strings:
		$a0 = { FA B8 ?? ?? 05 ?? ?? B1 ?? D3 E8 8C CB 03 C3 8E D8 8E D0 26 ?? ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 ?? D3 E3 EB }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDoteV12DemoSISTeam
{
strings:
		$a0 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv081v084Modified
{
strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }

condition:
		$a0 at entrypoint
}
	
	
rule DIETv100d
{
strings:
		$a0 = { FC 06 1E 0E 8C C8 01 ?? ?? ?? BA ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ASYLUMMusicFilev10
{
strings:
		$a0 = { 41 53 59 4C 55 4D 20 4D 75 73 69 63 20 46 6F 72 6D 61 74 20 56 31 2E 30 00 }

condition:
		$a0
}
	
	
rule ZipWorxSecureEXEv25ZipWORXTechnologiesLLCh
{
strings:
		$a0 = { E9 B8 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30 30 34 2D 32 30 30 37 20 5A 69 70 57 4F 52 58 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 2C 20 4C 4C 43 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 32 30 30 31 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 0D 0A 00 00 8B 44 24 04 23 05 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 02 FF E0 8B E5 5D C2 0C 00 80 3D ?? ?? ?? ?? 00 75 13 50 2B C0 50 E8 ?? ?? 00 00 83 C4 04 58 FE 05 ?? ?? ?? ?? ?? 94 9A 8D 91 9A 93 CC CD 00 B8 93 90 9D 9E 93 BE 93 93 90 9C 00 B8 93 90 9D 9E 93 B9 8D 9A 9A 00 B8 9A 8B B2 90 9B 8A 93 9A B7 9E 91 9B 93 9A BE 00 B8 9A 8B B2 90 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1338ObsidiumSoftware
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 }
	$a1 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MacromediaWindowsFlashProjectorPlayerv50
{
strings:
		$a0 = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 00 00 00 50 FF 15 80 61 44 00 F6 44 24 30 01 74 0B 8B 44 24 34 25 FF FF 00 00 EB 05 B8 0A 00 00 00 50 56 6A 00 6A 00 FF 15 74 61 44 00 50 E8 18 00 00 00 50 FF 15 78 61 44 00 5E 83 C4 44 C3 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule ORiEN211212FisunAlexander
{
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE ?? 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }

condition:
		$a0
}
	
	
rule ThinstallV27XJitit
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule CALSRastergraphicsformat
{
strings:
		$a0 = { 73 72 63 64 6F 63 69 64 3A 20 }

condition:
		$a0
}
	
	
rule hmimysprotect01hmimys
{
strings:
		$a0 = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 }

condition:
		$a0
}
	
	
rule ASProtectv10
{
strings:
		$a0 = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectv11
{
strings:
		$a0 = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov275a
{
strings:
		$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }

condition:
		$a0 at entrypoint
}
	
	
rule DOS16MDOSExtendercTenberrySoftwareInc19871995
{
strings:
		$a0 = { BF ?? ?? 8E C7 8E D7 BC ?? ?? 36 ?? ?? ?? ?? FF ?? ?? ?? 36 ?? ?? ?? ?? BE ?? ?? AC 8A D8 B7 00 ?? ?? 8B ?? ?? ?? 4F 8E C7 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner0132Lite003Anorganix
{
strings:
		$a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 ?? ?? ?? ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV119DllLZMA430ap0xnbspnbspSignbyfly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule VxSpanz
{
strings:
		$a0 = { E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84 }

condition:
		$a0 at entrypoint
}
	
	
rule Protectorv1111DDeMPEEnginev09DDeMCIv092
{
strings:
		$a0 = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackFullEdition117LZMA
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 73 26 00 00 8D 9D 58 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV118aPlib043ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 }

condition:
		$a0 at entrypoint
}
	
	
rule Pksmart10b
{
strings:
		$a0 = { BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01XCR011Anorganix
{
strings:
		$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PELockv106
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }

condition:
		$a0 at entrypoint
}
	
	
rule LaunchAnywherev4001
{
strings:
		$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 EB 19 3C 22 75 14 89 C0 8D 40 00 43 8A 03 84 C0 74 04 3C 22 75 F5 3C 22 75 01 43 8A 03 84 C0 74 0B 3C 20 74 07 3C 09 75 D9 EB 01 43 8A 03 84 C0 74 04 3C 20 7E F5 8D 45 B8 50 FF 15 E4 C1 44 00 8B 45 E4 25 01 00 00 00 74 06 0F B7 45 E8 EB 05 B8 0A 00 00 00 50 53 6A 00 6A 00 FF 15 08 C2 44 00 50 E8 63 15 FF FF 50 E8 EE 2A 00 00 59 8D 65 FC 5B }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeMSVCDLLMethod4emadiciush
{
strings:
		$a0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule GameGuardnProtect
{
strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE ?? ?? ?? ?? 31 FF 74 06 61 E9 4A 4D 50 30 8D BE ?? ?? ?? ?? 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B }
	$a1 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE ?? ?? ?? ?? 31 FF 74 06 61 E9 4A 4D 50 30 8D BE ?? ?? ?? ?? 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B 40 0C 8B 40 0C C7 40 20 00 10 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 85 C0 75 16 E9 12 00 00 00 31 C0 64 A0 20 00 00 00 85 C0 75 05 E9 01 00 00 00 61 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule nBinderv40
{
strings:
		$a0 = { 5C 6E 62 34 5F 74 6D 70 5F 30 31 33 32 34 35 34 33 35 30 5C 00 00 00 00 00 00 00 00 00 E9 55 43 4C FF 01 1A 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E 32 88 DB 0E A4 B8 DC 79 }

condition:
		$a0
}
	
	
rule HQRdatafile
{
strings:
		$a0 = { 48 00 00 00 ?? 02 00 00 ?? ?? 00 00 ?? ?? 00 00 }

condition:
		$a0
}
	
	
rule ZortechC
{
strings:
		$a0 = { E8 ?? ?? 2E FF ?? ?? ?? FC 06 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV2717V2719JititSignbyfly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 C1 FE FF FF E9 97 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EPExEPackV10EliteCodingGroup
{
strings:
		$a0 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 }

condition:
		$a0 at entrypoint
}
	
	
rule NorthStarPEShrinkerv13byLiuxingping
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 A3 ?? FF FF 85 C0 0F 84 06 03 00 00 89 85 63 ?? FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD 47 ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 A7 ?? FF FF FF B5 A3 ?? FF FF 56 57 FF 95 63 ?? FF FF 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB CE 68 00 80 00 00 6A 00 FF B5 63 ?? FF FF FF 95 A7 ?? FF FF 8D }

condition:
		$a0
}
	
	
rule WinZip32bitSFXv6xmodule
{
strings:
		$a0 = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 ?? ?? ?? ?? FF 15 }

condition:
		$a0 at entrypoint
}
	
	
rule MASMTASMsig4h
{
strings:
		$a0 = { C3 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }
	$a1 = { FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }

condition:
		$a0 or $a1
}
	
	
rule nSpackV13LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxEinstein
{
strings:
		$a0 = { 00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorbyVaskaunknownversignfrompinch210320062305
{
strings:
		$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 00 10 14 13 B8 00 10 14 13 3D 00 64 14 13 74 06 80 30 BC 40 EB F3 E8 00 00 00 00 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule VideoLanClient
{
strings:
		$a0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule ChinaProtectdummySignbyfly
{
strings:
		$a0 = { C3 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 56 8B ?? ?? ?? 6A 40 68 00 10 00 00 8D ?? ?? 50 6A 00 E8 ?? ?? ?? ?? 89 30 83 C0 04 5E C3 8B 44 ?? ?? 56 8D ?? ?? 68 00 40 00 00 FF 36 56 E8 ?? ?? ?? ?? 68 00 80 00 00 6A 00 56 E8 ?? ?? ?? ?? 5E C3 }

condition:
		$a0
}
	
	
rule MicrosoftRFulltextindexfile
{
strings:
		$a0 = { 6C 6C 2D 74 65 78 74 20 69 6E 64 65 78 }

condition:
		$a0
}
	
	
rule CrunchPEv10xx
{
strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 09 C6 85 }

condition:
		$a0 at entrypoint
}
	
	
rule VxTravJack883
{
strings:
		$a0 = { EB ?? 9C 9E 26 ?? ?? 51 04 ?? 7D ?? 00 ?? 2E ?? ?? ?? ?? 8C C8 8E C0 8E D8 80 ?? ?? ?? ?? 74 ?? 8A ?? ?? ?? BB ?? ?? 8A ?? 32 C2 88 ?? FE C2 43 81 }

condition:
		$a0 at entrypoint
}
	
	
rule WATCOMCC32RunTimeSystem19881995
{
strings:
		$a0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 }
	$a1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D ?? 43 2F 43 2B 2B 33 32 ?? 52 75 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RSCsProcessPatcherv151
{
strings:
		$a0 = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 C6 40 83 7E FC 00 0F 84 8F 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 E5 00 00 00 81 FF 72 21 73 63 74 7A 0F B7 1E 8B CF 8D 7E 02 C7 05 24 21 40 00 00 00 00 00 83 05 24 21 40 00 01 50 A1 28 21 40 00 39 05 24 21 40 00 58 0F 84 D8 00 00 00 60 6A 00 53 68 2C 21 40 00 51 FF 35 C4 20 40 00 E8 0A 01 00 00 61 60 FC BE 2C 21 40 00 8B CB F3 A6 61 75 C2 03 FB 60 E8 3E 00 00 00 6A 00 53 57 51 FF 35 C4 20 40 00 E8 FB 00 00 00 85 C0 0F 84 A2 00 00 00 61 03 FB 8B F7 E9 71 FF FF FF 60 FF 35 C8 20 40 00 E8 CB 00 00 00 61 C7 05 }

condition:
		$a0
}
	
	
rule kryptor9
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

condition:
		$a0 at entrypoint
}
	
	
rule Petite12c1998IanLuckh
{
strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0D 00 0F 00 11 00 13 00 17 00 1B 00 1F 00 23 00 2B 00 33 00 3B 00 43 00 53 00 63 00 73 00 83 00 A3 00 C3 00 E3 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 02 02 02 02 03 03 03 03 04 04 04 04 05 05 05 05 00 70 70 01 00 02 00 03 00 04 00 05 00 07 00 09 00 0D 00 11 00 19 00 21 00 31 00 41 00 61 00 81 00 C1 00 01 01 81 01 01 02 01 03 01 04 01 06 01 08 01 0C 01 10 01 18 01 20 01 30 01 40 01 60 00 00 00 00 01 01 02 02 03 03 04 04 05 05 06 06 07 07 08 08 09 09 0A 0A 0B 0B 0C 0C 0D 0D 10 11 12 00 08 07 09 06 0A 05 0B 04 0C 03 0D 02 0E 01 0F 58 2C 08 50 8B C8 8B D0 81 C1 ?? D2 00 00 81 C2 ?? ?? 00 00 89 20 8B E1 50 81 2C 24 00 ?? ?? ?? FF 30 50 80 04 24 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV111ap0xSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

condition:
		$a0 at entrypoint
}
	
	
rule PowerBASICCC40
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 68 05 00 00 E9 6E 03 }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePackV1XMethod2bagie
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 }

condition:
		$a0 at entrypoint
}
	
	
rule kryptor5
{
strings:
		$a0 = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }

condition:
		$a0 at entrypoint
}
	
	
rule kryptor6
{
strings:
		$a0 = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02MinGWGCC2x
{
strings:
		$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtectV13Xrisco
{
strings:
		$a0 = { 60 50 E8 01 00 00 00 75 83 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor239DLLcompressedresourceswwwstrongbitcom
{
strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 C1 C0 0F E9 ?? ?? ?? 00 87 04 24 58 89 45 FC E9 ?? ?? ?? FF FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 18 E9 ?? ?? ?? ?? 8B 55 08 09 42 F8 E9 ?? ?? ?? FF 83 7D F0 01 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 }

condition:
		$a0
}
	
	
rule PELockNTv202c
{
strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }

condition:
		$a0 at entrypoint
}
	
	
rule FreeBASIC016b
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 88 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 68 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D }
	$a1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 88 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 68 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D C3 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule RCryptorv16bv16cVaska
{
strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
	$a1 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PROMIDIMusicfile
{
strings:
		$a0 = { 52 49 46 46 ?? ?? ?? ?? 52 4D 49 44 }

condition:
		$a0
}
	
	
rule FSG110EngdulekxtBorlandDelphiBorlandC
{
strings:
		$a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }

condition:
		$a0 at entrypoint
}
	
	
rule FileShield
{
strings:
		$a0 = { 50 1E EB ?? 90 00 00 8B D8 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSplitter13SplitMethodBillPrisonerTPOC
{
strings:
		$a0 = { E8 00 00 00 00 5D 81 ED 08 12 40 00 E8 66 FE FF FF 55 50 8D 9D 81 11 40 00 53 8D 9D 21 11 40 00 53 6A 08 E8 76 FF FF FF 6A 40 68 00 30 00 00 68 00 01 00 00 6A 00 FF 95 89 11 40 00 89 85 61 10 40 00 50 68 00 01 00 00 FF 95 85 11 40 00 8D 85 65 10 40 00 50 FF B5 61 10 40 00 FF 95 8D 11 40 00 6A 00 68 80 00 00 00 6A 02 6A 00 ?? ?? ?? ?? 01 1F 00 FF B5 61 10 40 00 FF 95 91 11 40 00 89 85 72 10 40 00 6A 00 8D ?? ?? ?? ?? 00 50 FF B5 09 10 40 00 8D 85 F5 12 40 00 50 FF B5 72 10 40 00 FF 95 95 11 40 00 FF B5 72 10 40 00 FF 95 99 11 40 00 8D 85 0D 10 40 00 50 8D 85 1D 10 40 00 50 B9 07 00 00 00 6A 00 E2 FC }
	$a1 = { E9 FE 01 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 76 63 45 72 30 31 31 2E 74 6D 70 00 00 00 00 00 00 00 00 00 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 85 C0 0F 84 5F 02 00 00 8B 48 30 80 39 6B 74 07 80 39 4B 74 02 EB E7 80 79 0C 33 74 02 EB DF 8B 40 18 C3 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule PKLITEv1501
{
strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule Inbuildv10hard
{
strings:
		$a0 = { B9 ?? ?? BB ?? ?? 2E ?? ?? 2E ?? ?? 43 E2 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeShieldvxx
{
strings:
		$a0 = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidiumv1300ObsidiumSoftwareh
{
strings:
		$a0 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B 50 EB 03 8A 0B 93 33 C0 EB 02 28 B9 8B 00 EB 01 04 C3 EB 04 65 B3 54 0A E9 FA 00 00 00 EB 01 A2 E8 D5 FF FF FF EB 02 2B 49 EB 03 7C 3E 76 58 EB 04 B8 94 92 56 EB 01 72 64 67 8F 06 00 00 EB 02 23 72 83 C4 04 EB 02 A9 CB E8 47 26 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv20Vaska
{
strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? 02 00 00 F7 D1 83 F1 FF 59 BA 32 21 ?? 00 F7 D1 83 F1 FF F7 D1 83 F1 FF 80 02 E3 F7 D1 83 F1 FF C0 0A 05 F7 D1 83 F1 FF 80 02 6F F7 D1 83 F1 FF 80 32 A4 F7 D1 83 F1 FF 80 02 2D F7 D1 83 F1 FF 42 49 85 C9 75 CD 1C 4F 8D 5B FD 62 1E 1C 4F 8D 5B FD 4D 9D B9 ?? ?? ?? 1E 1C 4F 8D 5B FD 22 1C 4F 8D 5B FD 8E A2 B9 B9 E2 83 DB E2 E5 4D CD 1E BF 60 AB 1F 4D DB 1E 1E 3D 1E 92 1B 8E DC 7D EC A4 E2 4D E5 20 C6 CC B2 8E EC 2D 7D DC 1C 4F 8D 5B FD 83 56 8E E0 3A 7D D0 8E 9D 6E 7D D6 4D 25 06 C2 AB 20 CC 3A 4D 2D 9D 6B 0B 81 45 CC 18 4D 2D 1F A1 A1 6B C2 CC F7 E2 4D 2D 9E 8B 8B CC DE 2E 2D F7 1E AB 7D 45 92 30 8E E6 B9 7D D6 8E 9D 27 DA FD FD 1E 1E 8E DF B8 7D CF 8E A3 4D 7D DC 1C 4F 8D 5B FD 33 D7 1E 1E 1E A6 0B 41 A1 A6 42 61 6B 41 6B 4C 45 1E 21 F6 26 BC E2 62 1E 62 1E 62 1E 23 63 59 ?? 1E 62 1E 62 1E 33 D7 1E 1E 1E 85 6B C2 41 AB C2 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 20 33 9E 1E 1E 1E 85 A2 0B 8B C2 27 41 EB A1 A2 C2 1E C0 FD F0 FD 30 62 1E 33 7E 1E 1E 1E C6 2D 42 AB 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 C0 FD F0 8E 1D 1C 4F 8D 5B FD E0 00 33 5E 1E 1E 1E BF 0B EC C2 E6 42 A2 C2 45 1E C0 FD F0 FD 30 CE 36 CC F2 1C 4F 8D 5B FD }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv125
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? F3 0D }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv1Vaska
{
strings:
		$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }
	$a1 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule CipherWallSelfExtratorDecryptorConsolev15
{
strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 12 10 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 06 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv70DLL
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 ?? ?? 83 }
	$a1 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule CrypKeyKenonicControlsh
{
strings:
		$a0 = { 8B 1D ?? ?? 3E 00 83 FB 00 75 0A E8 3C 00 00 00 E8 ?? 0A 00 00 8B 44 24 08 50 E8 ?? 02 00 00 A1 ?? ?? 3E 00 83 F8 01 74 06 FF 25 14 ?? 3E 00 C3 C8 00 00 00 53 8B 5D 08 33 C0 8B 4D 0C 8B 13 33 D3 83 C3 04 03 C2 49 75 F4 5B C9 C3 56 68 ?? ?? 3E 00 E8 ?? 16 00 00 8B F0 68 ?? ?? 3E 00 56 E8 ?? 16 00 00 A3 ?? ?? 3E 00 68 ?? ?? 3E 00 56 E8 ?? 16 00 00 A3 ?? ?? 3E 00 68 ?? ?? 3E 00 56 E8 ?? ?? 00 00 A3 ?? ?? 3E 00 68 ?? ?? 3E 00 56 E8 ?? ?? 00 00 A3 ?? ?? 3E 00 68 ?? ?? 3E 00 56 E8 ?? ?? 00 00 A3 ?? ?? 3E 00 68 ?? ?? 3E 00 56 E8 ?? ?? 00 00 A3 ?? ?? 3E 00 68 ?? ?? 3E 00 56 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact200alpha38
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F }

condition:
		$a0
}
	
	
rule Packmanv10BrandonLaCombe
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA 8B E8 C6 06 E9 8B 43 0C 89 46 01 6A 04 68 00 10 00 00 FF 73 08 51 FF 55 08 8B }

condition:
		$a0 at entrypoint
}
	
	
rule XtremeProtectorv105
{
strings:
		$a0 = { E9 ?? ?? 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxGRUNT2Family
{
strings:
		$a0 = { 48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSmashervxx
{
strings:
		$a0 = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }

condition:
		$a0 at entrypoint
}
	
	
rule Shrinkv20
{
strings:
		$a0 = { E9 ?? ?? 50 9C FC BE ?? ?? 8B FE 8C C8 05 ?? ?? 8E C0 06 57 B9 }

condition:
		$a0 at entrypoint
}
	
	
rule USSR031bySpirit
{
strings:
		$a0 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 8C C9 30 C9 E3 01 C3 BE 32 ?? ?? ?? B0 ?? 30 06 8A 06 46 81 FE 00 ?? ?? ?? 7C F3 }

condition:
		$a0 at entrypoint
}
	
	
rule PeCompact253DLLSlimLoaderBitSumTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02WatcomCCDLL
{
strings:
		$a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }

condition:
		$a0 at entrypoint
}
	
	
rule LameCryptv10
{
strings:
		$a0 = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtector102exescrcomAshkbizDanehkarh
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }

condition:
		$a0
}
	
	
rule Cygwin32
{
strings:
		$a0 = { 55 89 E5 83 EC 04 83 3D }

condition:
		$a0 at entrypoint
}
	
	
rule PohernahCrypterV102Kas
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED DE 26 40 00 8B BD 05 28 40 00 8B 8D 0D 28 40 00 B8 25 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 09 28 40 00 31 C0 51 31 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 09 28 40 00 8B 85 11 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov210b2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorProtection150XCGSoftLabs
{
strings:
		$a0 = { EB 01 68 EB 01 ?? ?? ?? ?? 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 59 59 EB 01 C8 EB 02 }

condition:
		$a0
}
	
	
rule EncryptPEV12003318V12003518WFS
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxNecropolis1963
{
strings:
		$a0 = { B4 30 CD 21 3C 03 ?? ?? B8 00 12 CD 2F 3C FF B8 ?? ?? ?? ?? B4 4A BB 40 01 CD 21 ?? ?? FA 0E 17 BC ?? ?? E8 ?? ?? FB A1 ?? ?? 0B C0 }

condition:
		$a0 at entrypoint
}
	
	
rule PEArmor046ChinaCrackingGroup
{
strings:
		$a0 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 }
	$a1 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 A2 01 00 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 5D 81 ED 05 00 00 00 8D 75 3D 56 FF 55 31 8D B5 86 00 00 00 56 50 FF 55 2D 89 85 93 00 00 00 6A 04 68 00 10 00 00 FF B5 82 00 00 00 6A 00 FF 95 93 00 00 00 50 8B 9D 7E 00 00 00 03 DD 50 53 E8 04 00 00 00 5A 55 FF E2 60 8B 74 24 24 8B 7C 24 28 FC }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Armadillov190
{
strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule TheaPEInlinePatchExtraStealthSuperStealth
{
strings:
		$a0 = { E8 02 ?? ?? ?? EB 01 C3 3E 8B 44 24 FC 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinV071cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E }

condition:
		$a0 at entrypoint
}
	
	
rule Anti007V26LiuXingPingSignbyfly
{
strings:
		$a0 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 57 72 69 74 65 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 }

condition:
		$a0
}
	
	
rule Packman0001Bubbasoft
{
strings:
		$a0 = { 0F 85 ?? FF FF FF 8D B3 ?? ?? ?? ?? EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00 }

condition:
		$a0 at entrypoint
}
	
	
rule XHider10GlobaL
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 33 C0 89 45 EC B8 54 20 44 44 E8 DF F8 FF FF 33 C0 55 68 08 21 44 44 64 FF 30 64 89 20 8D 55 EC B8 1C 21 44 44 E8 E0 F9 FF FF 8B 55 EC B8 40 ?? ?? 44 E8 8B F5 FF FF 6A 00 6A 00 6A 02 6A 00 6A 01 68 00 00 00 40 A1 40 ?? ?? 44 E8 7E F6 FF FF 50 E8 4C F9 FF FF 6A 00 50 E8 4C F9 FF FF A3 28 ?? ?? 44 E8 CE FE FF FF 33 C0 5A 59 59 64 89 10 68 0F 21 44 44 8D 45 EC E8 F1 F4 FF FF C3 E9 BB F2 FF FF EB F0 E8 FC F3 FF FF FF FF FF FF 0E 00 00 00 63 3A 5C 30 30 30 30 30 30 31 2E 64 61 74 00 }
	$a1 = { 85 D2 74 23 8B 4A F8 41 7F 1A 50 52 8B 42 FC E8 30 00 00 00 89 C2 58 52 8B 48 FC E8 48 FB FF FF 5A 58 EB 03 FF 42 F8 87 10 85 D2 74 13 8B 4A F8 49 7C 0D FF 4A F8 75 08 8D 42 F8 E8 5C FA FF FF C3 8D 40 00 85 C0 7E 24 50 83 C0 0A 83 E0 FE 50 E8 2F FA FF FF 5A 66 C7 44 02 FE 00 00 83 C0 08 5A 89 50 FC C7 40 F8 01 00 00 00 C3 31 C0 C3 90 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule CRYPToCRACksPEProtectorV093LukasFleischerSignbyfly
{
strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 }

condition:
		$a0 at entrypoint
}
	
	
rule InnoSetupModule
{
strings:
		$a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }
	$a1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule PEQuake006byfORGAT
{
strings:
		$a0 = { E8 A5 00 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 3D ?? 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? 00 00 5B ?? 00 00 6E ?? 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 }

condition:
		$a0
}
	
	
rule EXEShieldV05Smoke
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 90 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2223protectedIATwwwstrongbitcom
{
strings:
		$a0 = { CC ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? B4 ?? ?? ?? 08 ?? ?? ?? 00 00 00 00 FF FF FF FF E8 ?? ?? ?? 04 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 }

condition:
		$a0 at entrypoint
}
	
	
rule RECrypt07xCruddRET
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B }

condition:
		$a0 at entrypoint
}
	
	
rule LGLZv104b
{
strings:
		$a0 = { FC 1E 06 0E 8C C8 ?? ?? ?? ?? BA ?? ?? 03 C2 8B D8 05 ?? ?? 8E DB 8E C0 33 F6 33 FF B9 ?? ?? F3 A5 4B 48 4A 79 }

condition:
		$a0 at entrypoint
}
	
	
rule UnnamedScrambler25Ap0ke
{
strings:
		$a0 = { 55 8B EC B9 0B 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 6C 3E 40 00 E8 F7 EA FF FF 33 C0 55 68 60 44 40 00 64 FF 30 64 89 20 BA 70 44 40 00 B8 B8 6C 40 00 E8 62 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 A1 EB FF FF BA E8 64 40 00 8B C3 8B 0D B8 6C 40 00 E8 }
	$a1 = { 55 8B EC B9 0B 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 6C 3E 40 00 E8 F7 EA FF FF 33 C0 55 68 60 44 40 00 64 FF 30 64 89 20 BA 70 44 40 00 B8 B8 6C 40 00 E8 62 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 A1 EB FF FF BA E8 64 40 00 8B C3 8B 0D B8 6C 40 00 E8 37 D3 FF FF C7 05 BC 6C 40 00 0A 00 00 00 BB 68 6C 40 00 BE 90 6C 40 00 BF E8 64 40 00 B8 C0 6C 40 00 BA 04 00 00 00 E8 07 EC FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 09 F3 FF FF 89 03 83 3B 00 0F 84 BB 04 00 00 B8 C0 6C 40 00 8B 16 E8 06 E2 FF FF B8 C0 6C 40 00 E8 24 E1 FF FF 8B D0 8B 03 8B 0E E8 D1 D2 FF FF 8B C7 A3 20 6E 40 00 8D 55 EC 33 C0 E8 0C D4 FF FF 8B 45 EC B9 1C 6E 40 00 BA 18 6E 40 00 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule PEncrypt20junkcode
{
strings:
		$a0 = { EB 25 00 00 F7 BF 00 00 00 00 00 00 00 00 00 00 12 00 E8 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 00 00 E8 00 00 00 00 5D 81 ED 2C 10 40 00 8D B5 14 10 40 00 E8 33 00 00 00 89 85 10 10 40 00 BF 00 00 40 00 8B F7 03 7F 3C 8B 4F 54 51 56 8D 85 }
	$a1 = { EB 25 00 00 F7 BF 00 00 00 00 00 00 00 00 00 00 12 00 E8 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 00 00 E8 00 00 00 00 5D 81 ED 2C 10 40 00 8D B5 14 10 40 00 E8 33 00 00 00 89 85 10 10 40 00 BF 00 00 40 00 8B F7 03 7F 3C 8B 4F 54 51 56 8D 85 23 10 40 00 50 6A 04 51 56 FF 95 10 10 40 00 5E 59 C6 06 00 46 E2 FA E9 AE 00 00 00 55 E8 00 00 00 00 5D 81 ED 77 10 40 00 8B D6 80 3E 00 74 03 46 EB F8 46 2B F2 8B CE 33 C0 66 89 85 06 10 40 00 8B B5 02 10 40 00 83 C6 3C 66 AD 03 85 02 10 40 00 8B 70 78 03 B5 02 10 40 00 83 C6 1C AD 03 85 02 10 40 00 89 85 08 10 40 00 AD 03 85 02 10 40 00 50 AD 03 85 02 10 40 00 89 85 0C 10 40 00 5E 56 AD 03 85 02 10 40 00 8B F0 8B FA 51 FC F3 A6 59 74 0D 5E 83 C6 04 66 FF 85 06 10 40 00 EB E0 5E 0F B7 85 06 10 40 00 D1 E0 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Armadillov177
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule VxTrivial25
{
strings:
		$a0 = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov171
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }

condition:
		$a0
}
	
	
rule PseudoSigner01MicrosoftVisualC70DLLAnorganix
{
strings:
		$a0 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 ?? ?? ?? ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMicrosoftVisualC6070
{
strings:
		$a0 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 }
	$a1 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 EB 02 82 53 EB 02 CD 20 87 FA 88 10 80 F3 CA EB 02 CD 20 40 03 D7 0B D0 4E 1B D2 EB 02 CD 20 2B D2 3B F2 75 AC F7 DA 80 C3 AF 91 1C 31 62 A1 61 20 61 71 A1 61 1F ?? ?? ?? 61 B4 49 6B 61 61 61 63 33 D6 66 EB 77 A7 73 33 24 13 E1 94 3C 05 14 63 60 75 85 D4 59 94 2A 60 75 85 D4 79 94 21 60 75 85 D4 82 14 63 A2 11 71 60 75 85 73 21 D4 5A D6 A0 0B 4C 3D 49 A4 61 61 61 8C 2C D6 71 49 99 61 61 61 4C 89 0D 32 49 D5 A2 74 2A 4C 7D F2 A9 22 41 69 0D 49 83 61 61 61 9E 61 DE 61 61 D4 6B E1 5D 66 D4 67 E4 59 E0 D8 63 }
	$a2 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00 }
	$a3 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }
	$a4 = { EB 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 }
	$a5 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }
	$a6 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint or $a4 at entrypoint or $a5 at entrypoint or $a6 at entrypoint
}
	
	
rule PseudoSigner01Morphine12
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule piritv15
{
strings:
		$a0 = { 5B 24 55 50 44 FB 32 2E 31 5D }

condition:
		$a0 at entrypoint
}
	
	
rule SoftSentryv30
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov19x
{
strings:
		$a0 = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov285
{
strings:
		$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }

condition:
		$a0 at entrypoint
}
	
	
rule MinGWGCCDLLv2xx
{
strings:
		$a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectvxx
{
strings:
		$a0 = { 60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD }

condition:
		$a0 at entrypoint
}
	
	
rule ExeShieldv17
{
strings:
		$a0 = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 }

condition:
		$a0 at entrypoint
}
	
	
rule NakedPackerV1XBigBoote
{
strings:
		$a0 = { 6A ?? E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF ?? ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 }

condition:
		$a0 at entrypoint
}
	
	
rule PackmanExecutableImagePacker0001bubba
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF }

condition:
		$a0 at entrypoint
}
	
	
rule FreeCryptor01build002GlOFF
{
strings:
		$a0 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 90 68 27 ?? ?? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }

condition:
		$a0
}
	
	
rule EXEShieldV06SMoKE
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 }
	$a1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 90 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule PseudoSigner02BorlandDelphiDLL
{
strings:
		$a0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackFullEdition117DLLLZMA
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealth25
{
strings:
		$a0 = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC }

condition:
		$a0
}
	
	
rule RLPack118DllLZMA430ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 08 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITEv100v103
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B }

condition:
		$a0 at entrypoint
}
	
	
rule ExeGuarder18Exeiconcomh
{
strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 }

condition:
		$a0
}
	
	
rule Shrinkerv32
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 00 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF }

condition:
		$a0 at entrypoint
}
	
	
rule Shrinkerv33
{
strings:
		$a0 = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule Petite13c1998IanLuck
{
strings:
		$a0 = { 9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 }

condition:
		$a0 at entrypoint
}
	
	
rule HASPHLProtectionV1XAladdinSignbyfly
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B 15 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv107bDLL
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }

condition:
		$a0 at entrypoint
}
	
	
rule CodeVirtualizerV1310OreansTechnologies
{
strings:
		$a0 = { 60 9C FC E8 00 00 00 00 5F 81 EF ?? ?? ?? ?? 8B C7 81 C7 ?? ?? ?? ?? 3B 47 2C 75 02 EB 2E 89 47 2C B9 A7 00 00 00 EB 05 01 44 8F ?? 49 0B C9 75 F7 83 7F 40 00 74 15 8B 77 40 03 F0 EB 09 8B 1E 03 D8 01 03 83 C6 04 83 3E 00 75 F2 8B 74 24 24 8B DE 03 F0 B9 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01LocklessIntroPackAnorganix
{
strings:
		$a0 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov250b3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCvxxDLL
{
strings:
		$a0 = { 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 }

condition:
		$a0 at entrypoint
}
	
	
rule PEBundlev02v20x
{
strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 }

condition:
		$a0 at entrypoint
}
	
	
rule SoftwareCompressV12BGSoftwareProtectTechnologies
{
strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PluginToExev100BoBBobSoft
{
strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 ?? ?? ?? 00 FF D3 83 C4 10 FF 95 B0 40 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SoftProtectwwwsoftprotectbyru
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? 01 }

condition:
		$a0 at entrypoint
}
	
	
rule SiliconRealmsInstallStub
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3 }
	$a1 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3 ?? ?? 40 00 33 F6 56 E8 ?? ?? 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 ?? ?? 00 00 FF 15 ?? 91 40 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 ?? ?? FF FF 89 75 D0 8D 45 A4 50 FF 15 ?? 91 40 00 E8 ?? ?? 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 ?? 91 40 00 50 E8 ?? ?? FF FF 89 45 A0 50 E8 ?? ?? FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 ?? ?? 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 ?? ?? FF FF 83 3D ?? ?? 40 00 01 75 05 }

condition:
		$a0 or $a1
}
	
	
rule Armadillov160a
{
strings:
		$a0 = { 55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakePCGuard4xxemadiciush
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakeMSVC60DLLemadicius
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 }

condition:
		$a0
}
	
	
rule eXPressorv1451CGSoftLabsh
{
strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? ?? 05 00 ?? ?? ?? A3 08 ?? ?? ?? A1 08 ?? ?? ?? B9 81 ?? ?? ?? 2B 48 18 89 0D 0C ?? ?? ?? 83 3D 10 ?? ?? ?? 00 74 16 A1 08 ?? ?? ?? 8B 0D 0C ?? ?? ?? 03 48 14 89 4D CC }

condition:
		$a0 at entrypoint
}
	
	
rule FucknJoyv10cUsAr
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 00 0B C0 0F 84 EC 00 00 00 89 85 4D 08 40 00 8D 85 51 08 40 00 50 FF B5 6C 08 40 00 E8 AF 02 00 00 0B C0 0F 84 CC 00 00 00 89 85 5C 08 40 00 8D 85 67 07 40 00 E8 7B 02 00 00 8D B5 C4 07 40 00 56 6A 64 FF 95 74 07 40 00 46 80 3E 00 75 FA C7 06 74 6D 70 2E 83 C6 04 C7 06 65 78 65 00 8D 85 36 07 40 00 E8 4C 02 00 00 33 DB 53 53 6A 02 53 53 68 00 00 00 40 8D 85 C4 07 40 00 50 FF 95 74 07 40 00 89 85 78 07 40 00 8D 85 51 07 40 00 E8 21 02 00 00 6A 00 8D 85 7C 07 40 00 50 68 00 ?? ?? 00 8D 85 F2 09 40 00 50 FF }

condition:
		$a0 at entrypoint
}
	
	
rule NsPackV2XLiuXingPing
{
strings:
		$a0 = { 6E 73 70 61 63 6B 24 40 }

condition:
		$a0
}
	
	
rule FreeJoinerSmallbuild017GlOFF
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 86 FF 86 DB 86 FF 68 00 01 00 00 68 18 20 40 00 6A 00 E8 FF 01 00 00 8A E4 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 18 20 40 00 E8 D5 01 00 00 A3 00 20 40 00 40 0F 84 97 01 00 00 8A E4 6A 02 6A 00 6A FB FF 35 00 20 40 00 E8 E0 01 00 00 86 FF 86 DB 86 FF 6A 00 8D 45 FC 50 6A 04 8D 45 F8 50 FF 35 00 20 40 00 E8 BD 01 00 00 8A E4 6A 00 8D 45 FC 50 6A 01 8D 45 F3 50 }
	$a1 = { E8 FE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule SoftWrap
{
strings:
		$a0 = { 52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 ?? ?? ?? E8 ?? 01 ?? ?? 60 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F }

condition:
		$a0 at entrypoint
}
	
	
rule JAMv211
{
strings:
		$a0 = { 50 06 16 07 BE ?? ?? 8B FE B9 ?? ?? FD FA F3 2E A5 FB 06 BD ?? ?? 55 CB }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphiDLL
{
strings:
		$a0 = { 55 8B EC 83 C4 B4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 40 }

condition:
		$a0 at entrypoint
}
	
	
rule SoftDefenderv112
{
strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 BE 01 00 00 03 C8 74 BD 75 BB E8 }

condition:
		$a0
}
	
	
rule PECompactv0978
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }

condition:
		$a0 at entrypoint
}
	
	
rule Setup2GoInstallerStub
{
strings:
		$a0 = { 5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72 }

condition:
		$a0
}
	
	
rule themida1005httpwwworeanscom
{
strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 }

condition:
		$a0 at entrypoint
}
	
	
rule ORiENv211DEMO
{
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D 20 2D 0D 0A 2D 2D 2D 2D 2D 2D 20 43 72 65 61 74 65 64 20 62 79 20 41 2E 20 46 69 73 75 6E 2C 20 31 39 39 34 2D 32 30 30 33 20 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 20 57 57 57 3A 20 68 74 74 70 3A 2F 2F 7A 61 6C 65 78 66 2E 6E 61 72 6F 64 2E 72 75 2F 20 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 20 65 2D 6D 61 69 6C 3A 20 7A 61 6C 65 78 66 40 68 6F 74 6D 61 69 6C 2E 72 75 20 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D }

condition:
		$a0 at entrypoint
}
	
	
rule UPXECLiPSElayer
{
strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv0977
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv13bVaska
{
strings:
		$a0 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 }
	$a1 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule mkfpackllydd
{
strings:
		$a0 = { E8 00 00 00 00 5B 81 EB 05 00 00 00 8B 93 9F 08 00 00 53 6A 40 68 00 10 00 00 52 6A 00 FF 93 32 08 00 00 5B 8B F0 8B BB 9B 08 00 00 03 FB 56 57 E8 86 08 00 00 83 C4 08 8D 93 BB 08 00 00 52 53 FF E6 }

condition:
		$a0
}
	
	
rule NortonSpeedDiskConfigurationfile
{
strings:
		$a0 = { 4E 6F 72 74 6F 6E 20 53 70 65 65 64 }

condition:
		$a0
}
	
	
rule ASPackv105b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }

condition:
		$a0 at entrypoint
}
	
	
rule MetaWareHighCRunTimeLibraryPharLapDOSExtender198389
{
strings:
		$a0 = { B8 ?? ?? 50 B8 ?? ?? 50 CB }

condition:
		$a0 at entrypoint
}
	
	
rule PELOCKnt204
{
strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandCDLL
{
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 }
	$a1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 8B }
	$a2 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3 8B }

condition:
		$a0 or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule AlexProtector04beta1byAlex
{
strings:
		$a0 = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 }

condition:
		$a0
}
	
	
rule MacromediaWindowsFlashProjectorPlayerv60
{
strings:
		$a0 = { 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

condition:
		$a0 at entrypoint
}
	
	
rule IMPostorPack10MahdiHezavehi
{
strings:
		$a0 = { BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PluginToExev102BoBBobSoft
{
strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED 32 42 40 00 50 8F 85 DD 40 40 00 50 FF 95 11 42 40 00 89 85 D9 40 40 00 FF 95 0D 42 40 00 50 FF 95 21 42 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 25 42 40 00 89 85 E1 40 40 00 EB 6C 6A 01 8F 85 DD 40 40 00 6A 58 6A 40 FF 95 15 42 40 00 89 85 D5 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 15 42 40 00 89 47 1C C7 07 58 00 }

condition:
		$a0 at entrypoint
}
	
	
rule XCFFileFormatbyAdelineSoftware
{
strings:
		$a0 = { 46 72 61 6D 65 4C 65 6E F4 0F }

condition:
		$a0
}
	
	
rule PKLITEv120
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 B4 4C CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv0761peexe
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 57 83 ?? ?? 31 DB EB }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv035alphaSignbyhot_UNP
{
strings:
		$a0 = { 8B F2 8B CA 03 4C 19 1C 03 54 1A 20 }

condition:
		$a0
}
	
	
rule PENinjamodified
{
strings:
		$a0 = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD }

condition:
		$a0 at entrypoint
}
	
	
rule DotFixNiceProtect21GPcHSoft
{
strings:
		$a0 = { E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealthv276WebToolMaster
{
strings:
		$a0 = { EB 65 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 59 4F 55 52 20 41 44 20 48 45 52 45 21 50 69 52 41 43 59 20 69 53 20 41 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor239DLLcompressedresources
{
strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 C1 C0 0F E9 ?? ?? ?? 00 87 04 24 58 89 45 FC E9 ?? ?? ?? FF FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 18 E9 ?? ?? ?? ?? 8B 55 08 09 42 F8 E9 ?? ?? ?? FF 83 7D F0 01 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 ?? ?? ?? 00 BA ?? ?? ?? ?? E8 ?? ?? ?? 00 A3 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 C3 83 C4 04 C3 E9 ?? ?? ?? FF 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? FF C1 C2 03 81 CA ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 03 C2 5A E9 ?? ?? ?? FF 81 E7 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? 89 07 E9 ?? ?? ?? ?? 0F 89 ?? ?? ?? ?? 87 14 24 5A 50 C1 C8 10 }

condition:
		$a0 at entrypoint
}
	
	
rule UnoPiX103110BaGiE
{
strings:
		$a0 = { 83 EC 04 C7 04 24 00 ?? ?? ?? C3 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 00 00 00 02 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 10 }

condition:
		$a0 at entrypoint
}
	
	
rule VideoLanClientUnknownCompiler
{
strings:
		$a0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule IonicWindSoftware
{
strings:
		$a0 = { 9B DB E3 9B DB E2 D9 2D 00 ?? ?? 00 55 89 E5 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeBJFNT13emadiciush
{
strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule vprotector13vcasm
{
strings:
		$a0 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 }

condition:
		$a0 at entrypoint
}
	
	
rule COMPACKv452
{
strings:
		$a0 = { BE ?? ?? E8 ?? ?? 5D 83 ?? ?? 55 50 53 51 52 0E 07 0E 1F 8B CE }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePackV11XMethod2bagie
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 }
	$a1 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

condition:
		$a0 or $a1
}
	
	
rule PCGuardv500d
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 85 E1 EA 41 00 9C EB 01 D5 9D EB 01 0B 58 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 89 85 F9 EA 41 00 9C EB 01 D5 9D EB 01 0B 89 9D E5 EA 41 00 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 8D E9 EA 41 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 89 95 ED EA 41 00 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 B5 F1 EA 41 00 9C EB 01 D5 9D EB 01 0B 89 }

condition:
		$a0 at entrypoint
}
	
	
rule LOCK98V10028keenvim
{
strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? EB 05 E9 ?? ?? ?? ?? EB 08 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv110b4
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44 }

condition:
		$a0 at entrypoint
}
	
	
rule VxBackfont900
{
strings:
		$a0 = { E8 ?? ?? B4 30 CD 21 3C 03 ?? ?? B8 ?? ?? BA ?? ?? CD 21 81 FA ?? ?? ?? ?? BA ?? ?? 8C C0 48 8E C0 8E D8 80 ?? ?? ?? 5A ?? ?? 03 ?? ?? ?? 40 8E D8 80 ?? ?? ?? 5A ?? ?? 83 }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystemv20
{
strings:
		$a0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D5 E8 6A FF FF FF 85 C0 0F 84 57 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 9C 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 75 0A C6 44 24 14 22 BE 01 40 43 00 FF 74 24 14 56 E8 8A 23 00 00 50 FF 15 80 71 40 00 8B F8 89 7C 24 18 EB 61 80 F9 20 75 06 40 80 38 20 74 FA 80 38 22 C6 44 24 14 20 75 06 40 C6 44 24 14 22 80 38 2F 75 31 40 80 38 53 75 0E 8A 48 01 80 C9 20 80 F9 20 75 03 }

condition:
		$a0
}
	
	
rule MetaWareHighCPharLapDOSExtender198389
{
strings:
		$a0 = { B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09 }

condition:
		$a0 at entrypoint
}
	
	
rule UPack011
{
strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 }

condition:
		$a0
}
	
	
rule Armadillo430aSiliconRealmsToolworksh
{
strings:
		$a0 = { 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43 4F 44 45 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 53 27 20 61 6E 64 20 27 25 53 27 00 00 00 00 50 75 74 53 74 72 69 6E 67 28 27 25 73 27 29 00 47 65 74 53 74 72 69 6E 67 28 29 2C 20 66 61 6C 73 65 00 00 47 65 74 53 }

condition:
		$a0
}
	
	
rule FreeJoinerSmallbuild031032GlOFF
{
strings:
		$a0 = { 50 32 ?? 66 8B C3 58 E8 ?? FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo36xSiliconRealmsToolworks
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 ?? 87 DB 7A F0 ?? ?? 61 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 ?? 8B 04 24 EB 03 7A 29 ?? C6 00 90 C3 ?? 70 F0 87 D2 71 07 ?? ?? 40 8B DB 7A 11 EB 08 ?? EB F7 EB C3 ?? 7A E9 70 DA 7B D1 71 F3 ?? 7B F3 71 D6 ?? 9D 61 83 ED 06 33 FF 47 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 EB 87 ?? 7A F0 ?? ?? 61 8B 9C BD AB 76 }

condition:
		$a0 at entrypoint
}
	
	
rule PEArmor04600759hying
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 }
	$a1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule Armadillo440SiliconRealmsToolworksh
{
strings:
		$a0 = { 31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8 73 DC F6 D1 05 42 55 53 79 73 74 65 6D 00 00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 44 44 45 20 50 72 6F 63 65 73 73 69 6E 67 00 00 53 77 50 44 44 45 00 00 44 00 44 00 45 00 20 00 50 00 72 00 6F 00 63 00 65 00 73 00 73 00 69 00 6E 00 67 00 00 00 00 00 53 00 77 00 50 00 44 00 44 00 45 00 00 00 00 00 3C 00 00 00 }

condition:
		$a0
}
	
	
rule Themida1201OreansTechnologiesh
{
strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 }
	$a1 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 11 02 00 00 00 00 00 }

condition:
		$a0 or $a1
}
	
	
rule Gleam100
{
strings:
		$a0 = { 83 EC 0C 53 56 57 E8 24 02 00 }

condition:
		$a0
}
	
	
rule PseudoSigner02MacromediaFlashProjector60
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

condition:
		$a0 at entrypoint
}
	
	
rule UtahRLEGraphicsformat
{
strings:
		$a0 = { 52 CC 00 00 00 00 ?? ?? ?? ?? 09 ?? 08 ?? 08 }

condition:
		$a0
}
	
	
rule MSVCv8procedure1recognizedh
{
strings:
		$a0 = { 55 8B EC 83 EC 10 A1 ?? ?? ?? ?? 83 65 F8 00 83 65 FC 00 53 57 BF 4E E6 40 BB 3B C7 BB 00 00 FF FF 74 0D 85 C3 74 09 F7 D0 A3 ?? ?? ?? ?? EB 60 56 8D 45 F8 50 FF 15 ?? ?? ?? ?? 8B 75 FC 33 75 F8 FF 15 ?? ?? ?? ?? 33 F0 FF 15 ?? ?? ?? ?? 33 F0 FF 15 ?? ?? ?? ?? 33 F0 8D 45 F0 50 FF 15 ?? ?? ?? ?? 8B 45 F4 33 45 F0 33 F0 3B F7 75 07 BE 4F E6 40 BB EB 0B 85 F3 75 07 8B C6 C1 E0 10 0B F0 89 35 ?? ?? ?? ?? F7 D6 89 35 ?? ?? ?? ?? 5E 5F 5B C9 C3 }

condition:
		$a0
}
	
	
rule SoftwareCompressBGSoftware
{
strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 }
	$a1 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 1A 0F 41 00 89 44 24 1C 61 C2 04 00 E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule VProtectorV13Xvcasm
{
strings:
		$a0 = { 00 00 00 00 55 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 64 69 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 }
	$a1 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule Upackv0399Dwing
{
strings:
		$a0 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 }
	$a1 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? 00 14 00 00 00 00 ?? ?? 00 ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? 00 ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 }
	$a2 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 10 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule UPXModifiedstub
{
strings:
		$a0 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPackerv100LZMA
{
strings:
		$a0 = { 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }

condition:
		$a0 at entrypoint
}
	
	
rule SCRAMv08a1
{
strings:
		$a0 = { B4 30 CD 21 3C 02 77 ?? CD 20 BC ?? ?? B9 ?? ?? 8B FC B2 ?? 58 4C }

condition:
		$a0 at entrypoint
}
	
	
rule Cryptic20Tughack
{
strings:
		$a0 = { B8 00 00 40 00 BB ?? ?? ?? 00 B9 00 10 00 00 BA ?? ?? ?? 00 03 D8 03 C8 03 D1 3B CA 74 06 80 31 ?? 41 EB F6 FF E3 }

condition:
		$a0 at entrypoint
}
	
	
rule KGBSFX
{
strings:
		$a0 = { 60 BE 00 A0 46 00 8D BE 00 70 F9 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin11Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

condition:
		$a0
}
	
	
rule PECompactv20betaJeremyCollake
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule DevCv4
{
strings:
		$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF }

condition:
		$a0
}
	
	
rule DevCv5
{
strings:
		$a0 = { 55 89 E5 83 EC 14 6A ?? FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

condition:
		$a0
}
	
	
rule VxVCLencrypted
{
strings:
		$a0 = { 01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3 }
	$a1 = { 01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule XPack167
{
strings:
		$a0 = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2xSoftCompleteDevelopement
{
strings:
		$a0 = { A4 ?? ?? 00 00 00 00 00 FF FF FF FF 3C ?? ?? 00 94 ?? ?? 00 D8 ?? ?? 00 00 00 00 00 FF FF FF FF }

condition:
		$a0
}
	
	
rule SharpGPBGraphicsformat
{
strings:
		$a0 = { 4D 00 00 00 00 ?? ?? ?? ?? 08 00 00 00 03 00 00 }

condition:
		$a0
}
	
	
rule VxCompiler
{
strings:
		$a0 = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }

condition:
		$a0 at entrypoint
}
	
	
rule BJFntv13
{
strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 }
	$a1 = { EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PseudoSigner02BJFNT11b
{
strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }

condition:
		$a0 at entrypoint
}
	
	
rule Go32Stubv200TDOSExtender
{
strings:
		$a0 = { 0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 3C }

condition:
		$a0 at entrypoint
}
	
	
rule REALbasic
{
strings:
		$a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
	
	
rule EXECryptor239compressedresourceswwwstrongbitcom
{
strings:
		$a0 = { 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 ?? ?? ?? ?? 00 00 23 C1 81 E9 ?? ?? ?? ?? 57 E9 ED 00 00 00 0F 88 ?? ?? ?? ?? E9 2C 0D 00 }

condition:
		$a0
}
	
	
rule PseudoSigner02DxPack10
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PackmanV0001Bubbasoft
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? 48 }

condition:
		$a0 at entrypoint
}
	
	
rule DJoinv07publicxorencryptiondrmist
{
strings:
		$a0 = { C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoinerSmallbuild033GlOFF
{
strings:
		$a0 = { 50 66 33 C3 66 8B C1 58 E8 AC FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor226DLLminimumprotectionwwwstrongbitcom
{
strings:
		$a0 = { 50 8B C6 87 04 24 68 ?? ?? ?? ?? 5E E9 ?? ?? ?? ?? 85 C8 E9 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 0F 81 ?? ?? ?? 00 81 FA ?? ?? ?? ?? 33 D0 E9 ?? ?? ?? 00 0F 8D ?? ?? ?? 00 81 D5 ?? ?? ?? ?? F7 D1 0B 15 ?? ?? ?? ?? C1 C2 ?? 81 C2 ?? ?? ?? ?? 9D E9 ?? ?? ?? ?? C1 }

condition:
		$a0
}
	
	
rule AnticrackSoftwareProtectorv109ACProtect
{
strings:
		$a0 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 C3 ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UnderGroundCrypterbyBooster2000
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 74 3C 00 11 E8 94 F9 FF FF E8 BF FE FF FF E8 0A F3 FF FF 8B C0 }

condition:
		$a0 at entrypoint
}
	
	
rule MicroJoiner16coban2k
{
strings:
		$a0 = { 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandPascalv70
{
strings:
		$a0 = { B8 ?? ?? 8E D8 8C ?? ?? ?? 8C D3 8C C0 2B D8 8B C4 05 ?? ?? C1 ?? ?? 03 D8 B4 ?? CD 21 0E }

condition:
		$a0 at entrypoint
}
	
	
rule DEF100Engbartxt
{
strings:
		$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule Armadillo430440SiliconRealmsToolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? 00 68 80 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 ?? ?? 00 33 D2 8A D4 89 15 30 ?? ?? 00 8B C8 81 E1 FF 00 00 00 89 0D 2C ?? ?? 00 C1 E1 08 03 CA 89 0D 28 ?? ?? 00 C1 E8 10 A3 24 }

condition:
		$a0
}
	
	
rule WiseInstallerStubv11010291
{
strings:
		$a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 E8 8A 08 80 F9 2F 74 2B 84 C9 74 1F 80 F9 3D 74 1A 8A 48 01 40 EB F1 33 F6 84 C9 74 D6 80 F9 20 74 }

condition:
		$a0 at entrypoint
}
	
	
rule PrivateEXEProtector18
{
strings:
		$a0 = { BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0 }

condition:
		$a0
}
	
	
rule TurboC1988
{
strings:
		$a0 = { 8C D8 BB ?? ?? 8E DB 8C D3 8B CC FA 8E ?? ?? ?? BC }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv155
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12 }

condition:
		$a0 at entrypoint
}
	
	
rule PolyCryptPE214b215JLabSoftwareCreationshsigned
{
strings:
		$a0 = { 50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45 }

condition:
		$a0
}
	
	
rule PECompactv156
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12 }

condition:
		$a0 at entrypoint
}
	
	
rule PGMPACKv013
{
strings:
		$a0 = { FA 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3 }

condition:
		$a0 at entrypoint
}
	
	
rule PGMPACKv014
{
strings:
		$a0 = { 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3 }

condition:
		$a0 at entrypoint
}
	
	
rule MorphnahBetaKas
{
strings:
		$a0 = { 2E 6E 61 68 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 A0 00 00 E0 }

condition:
		$a0 at entrypoint
}
	
	
rule PEiDBundleV102BoBBobSoft
{
strings:
		$a0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

condition:
		$a0 at entrypoint
}
	
	
rule LotusWordProdocumentfile
{
strings:
		$a0 = { 57 6F 72 64 50 72 6F ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C 57 50 37 }

condition:
		$a0
}
	
	
rule MEW10byNorthfox
{
strings:
		$a0 = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }

condition:
		$a0
}
	
	
	
	
rule Petitev211
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50 }

condition:
		$a0 at entrypoint
}
	
	
rule Petitev212
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50 }

condition:
		$a0 at entrypoint
}
	
	
rule MaskPEV20yzkzero
{
strings:
		$a0 = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }

condition:
		$a0
}
	
	
rule PseudoSigner01Morphine12Anorganix
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 E2 90 90 90 EB 08 82 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule y0dasCrypterv10
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85 }

condition:
		$a0 at entrypoint
}
	
	
rule EZIPv10
{
strings:
		$a0 = { E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C }

condition:
		$a0 at entrypoint
}
	
	
rule ZurenavaDOSExtenderv045v049
{
strings:
		$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 56 FC F3 A5 5F E9 }

condition:
		$a0 at entrypoint
}
	
	
	
	
rule ASProtectvIfyouknowthisversionpostonPEiDboard
{
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakePECompact14xemadiciush
{
strings:
		$a0 = { EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule BopCryptv10
{
strings:
		$a0 = { 60 BD ?? ?? ?? ?? E8 ?? ?? 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule nPackv11xxxNEOx
{
strings:
		$a0 = { 83 3D ?? ?? ?? 00 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 08 ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 ?? 02 00 00 E8 ?? 06 00 00 E8 ?? 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? 00 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 }

condition:
		$a0 at entrypoint
}
	
	
rule WindowsAnimationformat
{
strings:
		$a0 = { 52 49 46 46 ?? ?? ?? ?? 41 43 4F 4E 4C 49 53 54 }

condition:
		$a0
}
	
	
rule UPXv0896v102v105v124MarkusLaszlooverlay
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 ?? 8B 1E 83 ?? ?? 11 DB 72 ?? B8 01 00 00 00 01 DB 75 }

condition:
		$a0 at entrypoint
}
	
	
rule PEtitev20
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68 }

condition:
		$a0 at entrypoint
}
	
	
rule PEtitev21
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakeMSVCDLLMethod4emadicius
{
strings:
		$a0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 }

condition:
		$a0
}
	
	
rule MSLRHv01emadicius
{
strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 }

condition:
		$a0
}
	
	
rule Themida18xxOreansTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 }
	$a1 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule EXEJoinerv10
{
strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv120EngdulekxtBorlandDelphiBorlandC
{
strings:
		$a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB EE 90 14 2C 77 2A D3 EB 01 87 2A D3 E8 01 00 00 00 92 59 88 16 EB 02 52 08 46 EB 02 CD 20 4B 80 F1 C2 85 DB 75 AE C1 E0 04 EB 00 DA B2 82 5C 9B C7 89 98 4F 8A F7 ?? ?? ?? B1 4D DF B8 AD AC AB D4 07 27 D4 50 CF 9A D5 1C EC F2 27 77 18 40 4E A4 A8 B4 CB 9F 1D D9 EC 1F AD BC 82 AA C0 4C 0A A2 15 45 18 8F BB 07 93 BE C0 BC A3 B0 9D 51 D4 F1 08 22 62 96 6D 09 73 7E 71 A5 3A E5 7D 94 A3 96 99 98 72 B2 31 57 7B FA AE 9D 28 4F 99 EF A3 25 49 60 03 42 8B 54 53 5E 92 50 D4 52 4D C1 55 76 FD F7 8A FC 78 0C 82 87 0F }

condition:
		$a0 at entrypoint
}
	
	
rule EPackV14litefinal6aHguT
{
strings:
		$a0 = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01FSG10Anorganix
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov200b2200b3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule RAZOR1911encruptor
{
strings:
		$a0 = { E8 ?? ?? BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }

condition:
		$a0 at entrypoint
}
	
	
rule tElock051tE
{
strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 00 00 59 EB 01 EB AC 54 E8 03 00 00 00 5C EB 08 8D 64 24 04 FF 64 24 FC 6A 05 D0 2C 24 72 01 E8 01 24 24 5C F7 DC EB 02 CD 20 8D 64 24 FE F7 DC EB 02 CD 20 FE C8 E8 00 00 00 00 32 C1 EB 02 82 0D AA EB 03 82 0D 58 EB 02 1D 7A 49 EB 05 E8 01 00 00 00 7F AE 14 7E A0 77 76 75 74 }

condition:
		$a0 at entrypoint
}
	
	
rule VxFaxFreeTopo
{
strings:
		$a0 = { FA 06 33 C0 8E C0 B8 ?? ?? 26 ?? ?? ?? ?? 50 8C C8 26 ?? ?? ?? ?? 50 CC 58 9D 58 26 ?? ?? ?? ?? 58 26 ?? ?? ?? ?? 07 FB }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2021protectedIATwwwstrongbitcomSignByhaggar
{
strings:
		$a0 = { A4 ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? 94 ?? ?? ?? D8 ?? ?? ?? 00 00 00 00 FF FF FF FF B8 ?? ?? ?? D4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 60 ?? ?? ?? 70 ?? ?? ?? 84 ?? ?? ?? 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 }

condition:
		$a0
}
	
	
rule Joinersignfrompinch250320072010
{
strings:
		$a0 = { 81 EC 04 01 00 00 8B F4 68 04 01 00 00 56 6A 00 E8 7C 01 00 00 33 C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 56 E8 50 01 00 00 8B D8 6A 00 6A 00 6A 00 6A 02 6A 00 53 E8 44 01 }

condition:
		$a0 at entrypoint
}
	
	
rule yzPack10UsAr
{
strings:
		$a0 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeASPack212emadiciush
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 73 00 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	$a1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Pe123200644
{
strings:
		$a0 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 }

condition:
		$a0
}
	
	
rule MSLRH032afakeyodascryptor12emadicius
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC 90 2C 8A C0 C0 78 90 04 62 EB 01 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 }

condition:
		$a0
}
	
	
rule VxHymn1865
{
strings:
		$a0 = { E8 ?? ?? 5E 83 EE 4C FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 ?? ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 50 06 56 1E 0E 1F B8 00 C5 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule kkrunchyRyd
{
strings:
		$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 }
	$a1 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 EB 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 DB 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 BD 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 B2 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE ?? ?? ?? 00 BB ?? ?? ?? 00 55 46 AD 85 C0 74 29 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 0D 56 55 FF 53 04 AB 85 C0 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PECryptv100v101
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

condition:
		$a0 at entrypoint
}
	
	
rule PCIENCCryptor
{
strings:
		$a0 = { 06 50 43 49 45 4E }

condition:
		$a0
}
	
	
rule RCryptorv11Vaska
{
strings:
		$a0 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 }
	$a1 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 or $a1
}
	
	
rule PseudoSigner02JDPack1xJDProtect09
{
strings:
		$a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo444apublicbuildSiliconRealmsToolworksh
{
strings:
		$a0 = { 55 8B EC 83 EC 0C 53 56 57 8B 45 08 50 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 FC 8B 45 FC 51 B9 00 08 00 00 B9 06 00 00 00 F7 D1 0F C8 F7 D1 41 41 41 41 41 41 41 83 C1 04 41 41 41 41 83 C1 03 41 41 41 41 41 41 49 41 FE C1 FE C1 FE C1 83 C1 0D FE C1 FE C1 FE C1 FE C1 FE C1 83 C1 0A 49 52 BA 04 00 00 00 03 CA 41 5A 0F C8 23 C1 59 F7 D8 1B C0 F7 D8 5A 89 45 F4 8B 0D ?? ?? ?? ?? 33 0D ?? ?? ?? ?? D1 E1 89 4D F8 83 7D F4 00 74 09 8B 55 F8 83 CA 01 89 55 F8 8B 45 F8 50 FF 15 ?? ?? ?? ?? 83 C4 04 5F 5E 5B 8B E5 5D C3 55 8B EC 83 EC 0C 53 56 57 8B 45 08 50 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 FC 8B 45 FC 53 BB 80 00 00 00 EB 05 BB 04 00 00 00 BB 32 00 00 00 F7 D3 0F C8 F7 D3 43 43 83 E0 00 83 C3 08 4B 51 B9 04 00 00 00 03 D9 43 59 0F C8 40 5B 89 45 F4 8B 0D ?? ?? ?? ?? 33 0D ?? ?? ?? ?? D1 E1 89 4D F8 83 7D F4 00 74 09 8B 55 F8 83 CA 01 89 55 F8 8B 45 F8 50 FF 15 ?? ?? ?? ?? 83 C4 04 5F 5E 5B 8B E5 5D C3 55 8B EC 83 EC 0C 53 56 57 8B 45 08 50 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 FC 8B 45 FC 70 07 7C 03 EB 05 E9 74 FB EB F9 53 BB FF FF 00 00 23 C3 51 B5 2C 80 ED 01 80 ED 20 FE CD FE CD 80 ED 04 FE CD 80 ED 03 FE CD 22 E5 B1 70 80 E9 02 FE C9 FE C9 FE C9 80 E9 06 F6 D0 0F C9 F6 D0 0F C9 FE C9 FE C9 80 E9 10 FE C9 FE C9 80 C1 0C FE C9 FE C9 FE C9 70 07 7C 03 EB 05 C7 74 FB EB F9 FE C9 FE C9 FE C9 FE C9 80 E9 10 80 E9 01 FE C9 FE C9 FE C9 FE C9 FE C9 FE C9 FE C9 FE C9 F7 D1 0F C8 F7 D1 0F C8 FE C1 80 C1 02 22 C1 59 5B 85 C0 0F 85 94 00 00 00 8B 45 FC 53 BB 00 08 00 00 EB 05 BB 80 00 00 00 BB 72 00 00 00 F7 D3 0F C8 F7 D3 43 43 83 C3 08 4B 51 B9 04 00 00 00 03 D9 43 59 0F C8 23 C3 5B F7 D8 1B C0 40 5A 8B C8 51 8B 45 FC 52 BA FF FF }

condition:
		$a0
}
	
	
rule CERBERUSv20
{
strings:
		$a0 = { 9C 2B ED 8C ?? ?? 8C ?? ?? FA E4 ?? 88 ?? ?? 16 07 BF ?? ?? 8E DD 9B F5 B9 ?? ?? FC F3 A5 }

condition:
		$a0 at entrypoint
}
	
	
rule UPolyX0xDelikon
{
strings:
		$a0 = { 81 FD 00 FB FF FF 83 D1 ?? 8D 14 2F 83 FD FC 76 ?? 8A 02 42 88 07 47 49 75 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv303
{
strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53 }

condition:
		$a0 at entrypoint
}
	
		
	
rule VxDanishtiny
{
strings:
		$a0 = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXFreakv01BorlandDelphiHMX0101
{
strings:
		$a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeASPack211demadiciush
{
strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02YodasProtector102Anorganix
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule Shrinkerv34
{
strings:
		$a0 = { 83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }
	$a1 = { BB ?? ?? BA ?? ?? 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule NsPacKV34V35LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84 }

condition:
		$a0 at entrypoint
}
	
	
rule DualseXe10
{
strings:
		$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 08 03 00 00 89 28 33 FF 8D 85 7D 02 00 00 8D 8D 08 03 00 00 2B C8 8B 9D 58 03 00 00 E8 1C 02 00 00 8D 9D 61 02 00 00 8D B5 7C 02 00 00 46 80 3E 00 74 24 56 FF 95 0A 04 00 00 46 80 3E 00 }
	$a1 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 08 03 00 00 89 28 33 FF 8D 85 7D 02 00 00 8D 8D 08 03 00 00 2B C8 8B 9D 58 03 00 00 E8 1C 02 00 00 8D 9D 61 02 00 00 8D B5 7C 02 00 00 46 80 3E 00 74 24 56 FF 95 0A 04 00 00 46 80 3E 00 75 FA 46 80 3E 00 74 E7 50 56 50 FF 95 0E 04 00 00 89 03 58 83 C3 04 EB E3 8D 85 24 03 00 00 50 68 1F 00 02 00 6A 00 8D 85 48 03 00 00 50 68 01 00 00 80 FF 95 69 02 00 00 83 BD 24 03 00 00 00 0F 84 8B 00 00 00 C7 85 28 03 00 00 04 00 00 00 8D 85 28 03 00 00 50 8D 85 20 03 00 00 50 8D 85 6C 03 00 00 50 6A 00 8D 85 62 03 00 00 50 FF B5 24 03 00 00 FF 95 71 02 00 00 83 BD 20 03 00 00 01 7E 02 EB 20 6A 40 8D 85 73 03 00 00 50 8D 85 82 03 00 00 50 6A 00 FF 95 61 02 00 00 6A 00 FF 95 65 02 00 00 FF 8D 20 03 00 00 FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule NoodleCryptv200EngNoodleSpa
{
strings:
		$a0 = { EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02 04 00 00 EB 01 9A E8 19 07 00 00 EB 01 9A E8 9C 00 00 00 EB 01 9A E8 9C 06 00 00 E8 00 00 00 00 0F 7E F8 EB 01 9A 8B F8 C3 E8 00 00 00 00 58 EB 01 9A 25 00 F0 FF FF 8B F8 EB 01 9A 0F 6E F8 C3 8B D0 EB 01 9A 81 C2 C8 00 00 00 EB 01 9A B9 00 17 00 00 EB 01 9A C0 0A 06 EB 01 9A 80 2A 15 EB 01 9A 42 E2 EE 0F 6E C0 EB 01 9A 0F 7E C0 EB 01 9A 8B D0 00 85 EB A5 F5 65 4B 45 45 00 85 EB B3 65 07 45 45 00 85 EB 75 C7 C6 00 85 EB 65 CF 8A 00 85 EB D5 FD C0 00 85 EB 7F E5 05 05 05 00 85 EB 7F 61 06 45 45 00 85 EB 7F }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePECompact14xemadicius
{
strings:
		$a0 = { EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A }

condition:
		$a0
}
	
	
rule DiskDupecMSDConfigurationfile
{
strings:
		$a0 = { 4D 53 44 20 44 61 74 61 20 56 65 72 73 }

condition:
		$a0
}
	
	
rule WARNINGTROJANHuiGeZi
{
strings:
		$a0 = { 55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDoteV1xSISTeam
{
strings:
		$a0 = { 68 ?? ?? 00 00 E8 ?? FD FF FF 68 ?? ?? 00 00 E8 ?? FD FF FF 68 90 03 00 00 E8 ?? FD FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? FD FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule pscrambler12byp0ke
{
strings:
		$a0 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 ?? ?? ?? ?? 10 E8 2D F3 FF FF 33 C0 55 68 E8 31 00 10 64 FF 30 64 89 20 8D 45 E0 E8 53 F5 FF FF 8B 45 E0 8D 55 E4 E8 30 F6 FF FF 8B 45 E4 8D 55 E8 E8 A9 F4 FF FF 8B 45 E8 8D 55 EC E8 EE F7 FF FF 8B 55 EC }
	$a1 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 ?? ?? ?? ?? 10 E8 2D F3 FF FF 33 C0 55 68 E8 31 00 10 64 FF 30 64 89 20 8D 45 E0 E8 53 F5 FF FF 8B 45 E0 8D 55 E4 E8 30 F6 FF FF 8B 45 E4 8D 55 E8 E8 A9 F4 FF FF 8B 45 E8 8D 55 EC E8 EE F7 FF FF 8B 55 EC B8 C4 54 00 10 E8 D9 EC FF FF 83 3D C4 54 00 10 00 0F 84 05 01 00 00 80 3D A0 40 00 10 00 74 41 A1 C4 54 00 10 E8 D9 ED FF FF E8 48 E0 FF FF 8B D8 A1 C4 54 00 10 E8 C8 ED FF FF 50 B8 C4 54 00 10 E8 65 EF FF FF 8B D3 59 E8 69 E1 FF FF 8B C3 E8 12 FA FF FF 8B C3 E8 33 E0 FF FF E9 AD 00 00 00 B8 05 01 00 00 E8 0C E0 FF FF 8B D8 53 68 05 01 00 00 E8 57 F3 FF FF 8D 45 DC 8B D3 E8 39 ED FF FF 8B 55 DC B8 14 56 00 10 B9 00 32 00 10 E8 BB ED FF FF 8B 15 14 56 00 10 B8 C8 54 00 10 E8 53 E5 FF FF BA 01 00 00 00 B8 C8 54 00 10 E8 8C E8 FF FF E8 DF E0 FF FF 85 C0 75 52 6A 00 A1 C4 54 00 10 E8 3B ED FF FF 50 B8 C4 54 00 10 E8 D8 EE FF FF 8B D0 B8 C8 54 00 10 59 E8 3B E6 FF FF E8 76 E0 FF FF B8 C8 54 00 10 E8 4C E6 FF FF E8 67 E0 FF FF 6A 00 6A 00 6A 00 A1 14 56 00 10 E8 53 EE FF FF 50 6A 00 6A 00 E8 41 F3 FF FF 80 3D 9C 40 00 10 00 74 05 E8 EF FB FF FF 33 C0 5A 59 59 64 89 10 68 EF 31 00 10 8D 45 DC BA 05 00 00 00 E8 7D EB FF FF C3 E9 23 E9 FF FF EB EB 5B E8 63 EA FF FF 00 00 00 FF FF FF FF 08 00 00 00 74 65 6D 70 2E 65 78 65 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PseudoSigner01JDPack1xJDProtect09Anorganix
{
strings:
		$a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV22XV2308Jitit
{
strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }

condition:
		$a0 at entrypoint
}
	
	
	
rule GXProtector12GurueXe
{
strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01StelthPE101
{
strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA ?? ?? ?? ?? FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule NTkrnlSecureSuiteNTkrnlteamh
{
strings:
		$a0 = { 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	$a1 = { 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 79 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule Armadillo50DllSiliconRealmsToolworks
{
strings:
		$a0 = { 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 E5 24 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 8F 15 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 20 15 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 D7 23 00 00 59 89 7D FC FF 75 08 E8 EC 53 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 2B C5 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 19 ED FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 7D 22 00 00 59 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule TurboPascalDesktopFile
{
strings:
		$a0 = { 54 75 72 62 6F 20 50 61 73 63 61 6C 20 44 65 73 6B 74 6F 70 }

condition:
		$a0
}
	
	
rule ObsidiumV1350ObsidiumSoftware
{
strings:
		$a0 = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 }

condition:
		$a0 at entrypoint
}
	
	
rule SVKPv142PavolCervenh
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 49 DC EC 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 2D 67 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 2D 67 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 39 67 00 00 5D 6A FF FF 95 31 67 }

condition:
		$a0 at entrypoint
}
	
	
rule GoatsMutilatorv16Goat_e0f
{
strings:
		$a0 = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectv123RC1
{
strings:
		$a0 = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Packv139
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40 }

condition:
		$a0 at entrypoint
}
	
	
rule PUNiSHERv15DEMOFEUERRADERAHTeam
{
strings:
		$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 24 EB 04 64 6B 88 18 89 85 9C C2 41 00 EB 04 64 6B 88 18 58 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv2xx
{
strings:
		$a0 = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
	$a1 = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ObsidiumV1322ObsidiumSoftware
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv140b2v140b4
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackFullEdition117Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF }

condition:
		$a0 at entrypoint
}
	
	
rule CryptoLockv202EngRyanThian
{
strings:
		$a0 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 }
	$a1 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 55 00 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 01 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 }
	$a2 = { 60 BE ?? 90 40 00 8D BE ?? ?? FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 55 00 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 01 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule SLROPTLINK
{
strings:
		$a0 = { BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB B4 30 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule vfpexeNcv600WangJianGuo
{
strings:
		$a0 = { 60 E8 01 00 00 00 63 58 E8 01 00 00 00 7A 58 2D 0D 10 40 00 8D 90 C1 10 40 00 52 50 8D 80 49 10 40 00 5D 50 8D 85 65 10 40 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }

condition:
		$a0 at entrypoint
}
	
	
rule Anti007V27V35NsPacKPrivate
{
strings:
		$a0 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 54 }

condition:
		$a0 at entrypoint
}
	
	
rule XPEORv099b
{
strings:
		$a0 = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
	$a1 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule eXPressorV145xCGSoftLabs
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 83 65 ?? 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 ?? ?? ?? 00 A1 ?? ?? ?? 00 B9 ?? ?? ?? 00 2B 48 18 89 0D ?? ?? ?? 00 83 3D }

condition:
		$a0 at entrypoint
}
	
	
rule MetrowerksCodeWarriorDLLv20
{
strings:
		$a0 = { 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 ?? ?? ?? ?? 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9 }

condition:
		$a0
}
	
	
rule PeCompact2253276BitSumTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 C9 11 00 10 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 5A 8B F8 50 52 8B 33 8B 43 20 03 C2 8B 08 89 4B 20 8B 43 1C 03 C2 8B 08 89 4B 1C 03 F2 8B 4B 0C 03 CA 8D 43 1C 50 57 56 FF }

condition:
		$a0
}
	
	
rule FSGv100Engdulekxt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 51 FF FF FF 5F BB 28 ?? ?? 00 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE 0F 74 EF FE 0F 75 06 47 FF 37 AF EB 09 FE 0F 0F 84 ?? ?? ?? FF 57 55 FF 53 04 09 06 AD 75 DB 8B EC C3 1C ?? ?? 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01BorlandDelphi50KOLMCKAnorganix
{
strings:
		$a0 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 08 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0E 00 90 90 90 90 90 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0A 00 00 00 90 90 90 90 90 00 00 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule DotFixNiceProtectV21GPcHSoftSignByhaggar
{
strings:
		$a0 = { E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 B8 ?? ?? ?? ?? 03 C5 50 B8 ?? ?? ?? ?? 03 C5 FF 10 BB ?? ?? ?? ?? 03 DD 83 C3 0C 53 50 B8 ?? ?? ?? ?? 03 C5 FF 10 6A 40 68 00 10 00 00 FF 74 24 2C 6A 00 FF D0 89 44 24 1C 61 C3 }

condition:
		$a0
}
	
	
rule FlyCrypter10ut1lz
{
strings:
		$a0 = { 53 56 57 55 BB 2C ?? ?? 44 BE 00 30 44 44 BF 20 ?? ?? 44 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 44 44 00 74 06 FF 15 58 30 44 44 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 20 30 44 44 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 18 30 44 44 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 2F FA FF FF FF 15 24 30 44 44 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 ?? ?? 44 00 74 06 FF 15 10 ?? ?? 44 8B 06 50 E8 51 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 44 44 E8 26 FF FF FF C3 }
	$a1 = { 55 8B EC 83 C4 F0 53 B8 18 22 44 44 E8 7F F7 FF FF E8 0A F1 FF FF B8 09 00 00 00 E8 5C F1 FF FF 8B D8 85 DB 75 05 E8 85 FD FF FF 83 FB 01 75 05 E8 7B FD FF FF 83 FB 02 75 05 E8 D1 FD FF FF 83 FB 03 75 05 E8 87 FE FF FF 83 FB 04 75 05 E8 5D FD FF FF 83 FB 05 75 05 E8 B3 FD FF FF 83 FB 06 75 05 E8 69 FE FF FF 83 FB 07 75 05 E8 5F FE FF FF 83 FB 08 75 05 E8 95 FD FF FF 83 FB 09 75 05 E8 4B FE FF FF 5B E8 9D F2 FF FF 90 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule UPXLockv11CyberDoomBob
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? 00 60 }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftPiMPInstallSystem1x
{
strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 }

condition:
		$a0
}
	
	
rule muckisprotectorIImucki
{
strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 E8 85 C0 74 12 64 8B 3D 18 00 00 00 8B 7F 30 0F B6 47 02 85 C0 74 01 C3 C7 04 24 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 }
	$a1 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 E8 85 C0 74 12 64 8B 3D 18 00 00 00 8B 7F 30 0F B6 47 02 85 C0 74 01 C3 C7 04 24 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 C3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule VcasmProtector10
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 E8 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 05 00 00 00 0F 01 EB 05 E8 EB FB 00 00 83 C4 04 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule NullsoftInstallSystemv20b2v20b3
{
strings:
		$a0 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin1304Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 }

condition:
		$a0
}
	
	
rule GardianAngel10
{
strings:
		$a0 = { 06 8C C8 8E D8 8E C0 FC BF ?? ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule eXpressorv12CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 }

condition:
		$a0 at entrypoint
}
	
	
rule RSCsProcessPatcherv14
{
strings:
		$a0 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 20 40 00 68 A2 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 7C 01 00 00 85 C0 0F 84 2A 01 00 00 B8 00 60 40 00 8B 00 A3 1C 22 40 00 BE 40 60 40 00 83 7E FC 00 0F 84 F6 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 83 00 00 00 81 FF 72 21 73 63 0F 84 DD 00 00 00 33 DB 66 8B 1E 8B CF 8D 7E 02 C7 05 EA 21 40 00 00 00 00 00 83 05 EA 21 40 00 01 50 A1 1C 22 40 00 39 05 EA 21 40 00 58 0F 84 C1 00 00 00 60 6A 00 53 68 EA 20 40 00 51 FF 35 92 20 40 00 E8 EB 00 00 00 61 60 FC BE EA 20 40 00 8B CB F3 A6 61 75 C2 03 }

condition:
		$a0
}
	
	
rule Armadillov190b1
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule fromNORMANAntiVirusUtilites
{
strings:
		$a0 = { E8 ?? ?? 5B 52 45 2F 4E 44 44 53 5D 0D 0A }

condition:
		$a0 at entrypoint
}
	
	
rule PatchCreationWizardv12SeekandDestroyPatch
{
strings:
		$a0 = { E8 C5 05 00 00 6A 00 E8 5E 05 00 00 A3 CE 39 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 72 05 00 00 6A 00 E8 2F 05 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 CE 39 40 00 E8 61 05 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 63 05 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 5A 05 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 4B 05 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 3C 05 00 00 6A 00 FF 75 08 E8 0E 05 00 00 A3 CA 39 40 00 C7 05 D2 39 40 00 2C 00 00 00 C7 05 D6 39 40 00 10 00 00 00 C7 05 DA 39 40 00 00 08 00 00 68 D2 39 40 00 6A 01 6A FF FF 35 CA 39 40 00 E8 DD 04 00 00 C7 05 DA 39 40 00 00 00 00 00 C7 05 F6 39 40 00 00 30 40 00 C7 05 FA 39 40 00 01 00 00 00 68 D2 39 40 00 6A 01 6A FF FF 35 CA 39 40 00 E8 AB 04 00 00 EB 5F EB 54 }

condition:
		$a0
}
	
	
rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCASM
{
strings:
		$a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall25xxJtit
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? ?? 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }

condition:
		$a0 at entrypoint
}
	
	
rule hmimysPacker10hmimys
{
strings:
		$a0 = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 }
	$a1 = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 }

condition:
		$a0 or $a1
}
	
	
rule PseudoSigner02Armadillo300
{
strings:
		$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeSVKP111emadiciush
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorv1501OptionsProtectionCGSoftLabs
{
strings:
		$a0 = { 5E 00 00 80 00 00 00 68 91 5D D4 27 35 C5 5A 4C A5 40 48 C4 08 4E C0 }

condition:
		$a0 at entrypoint
}
	
	
rule JDPack
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD 45 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualC70DLL
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 }

condition:
		$a0
}
	
	
rule MorphineV33Holy_FatherRatter29A
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }

condition:
		$a0
}
	
	
rule PESpinv1304Cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

condition:
		$a0 at entrypoint
}
	
	
rule diPacker1xdiProtectorSoftware
{
strings:
		$a0 = { 0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5 }

condition:
		$a0 at entrypoint
}
	
	
rule tElock098SpecialBuildforgotheXer
{
strings:
		$a0 = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01DEF10Anorganix
{
strings:
		$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov260c
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 F4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 F4 }

condition:
		$a0 at entrypoint
}
	
	
rule MASMTASMsig2h
{
strings:
		$a0 = { C2 ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }

condition:
		$a0
}
	
	
rule Armadillov260a
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4 }

condition:
		$a0 at entrypoint
}
	
	
rule BookManagerv9510
{
strings:
		$a0 = { FC A3 ?? ?? 89 1E ?? ?? 49 89 0E ?? ?? BB ?? ?? 8C 1F 83 ?? ?? 89 ?? ?? B8 ?? ?? 50 89 ?? ?? F7 D0 50 }

condition:
		$a0 at entrypoint
}
	
	
rule ThemidaWinLicenseV10XV17XDLLOreansTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 ?? 89 48 01 61 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor12CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }

condition:
		$a0 at entrypoint
}
	
	
rule NeoLitev10
{
strings:
		$a0 = { 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25 }
	$a1 = { E9 9B 00 00 00 A0 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ExeBundlev30standardloader
{
strings:
		$a0 = { 00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB }

condition:
		$a0 at entrypoint
}
	
	
rule ProtectionPlusvxx
{
strings:
		$a0 = { 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 ?? ?? E8 DD ?? ?? ?? 89 85 1F 03 ?? ?? 6A 40 68 ?? 10 ?? ?? 8B 85 }
	$a1 = { 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 ?? ?? E8 DD ?? ?? ?? 89 85 1F 03 ?? ?? 6A 40 68 ?? 10 ?? ?? 8B 85 28 ?? ?? ?? 50 6A }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RLPackFullEdition117aPLib
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 74 1F 00 00 8D 9D 1E 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 }

condition:
		$a0 at entrypoint
}
	
	
rule RECv032
{
strings:
		$a0 = { 06 1E 52 B8 ?? ?? 1E CD 21 86 E0 3D }

condition:
		$a0 at entrypoint
}
	
	
rule VideoCDfile
{
strings:
		$a0 = { 52 49 46 46 ?? ?? ?? ?? 43 44 58 41 66 6D 74 }

condition:
		$a0
}
	
	
rule LGLZv104com
{
strings:
		$a0 = { BF ?? ?? 3B FC 72 19 B4 09 BA 12 01 CD 21 B4 4C CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptorV22Xsoftcompletecom
{
strings:
		$a0 = { FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00 }

condition:
		$a0
}
	
	
rule SVKPv143PavolCervenh
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 49 DC CE 05 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 2D 67 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 2D 67 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 39 67 00 00 5D 6A FF FF 95 31 67 }

condition:
		$a0 at entrypoint
}
	
	
rule COMPACKv51
{
strings:
		$a0 = { BD ?? ?? 50 06 8C CB 03 DD 8C D2 4B 8E DB BE ?? ?? BF ?? ?? 8E C2 B9 ?? ?? F3 A5 4A 4D 75 ?? 8B F7 8E DA 0E 07 06 16 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallVirtualizationSuite30353043ThinstallCompany
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01CrunchPEHeuristicAnorganix
{
strings:
		$a0 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv120EngdulekxtBorlandC
{
strings:
		$a0 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 EB 02 56 7B 2A D3 E8 01 00 00 00 ED 58 88 16 13 C3 46 EB 02 CD 20 4B EB 02 CD 20 2B C9 3B D9 75 A1 E8 02 00 00 00 D7 6B 58 EB 00 9E 96 6A 28 67 AB 69 54 03 3E 7F ?? ?? ?? 31 0D 63 44 35 38 37 18 87 9F 10 8C 37 C6 41 80 4C 5E 8B DB 60 4C 3A 28 08 30 BF 93 05 D1 58 13 2D B8 86 AE C8 58 16 A6 95 C5 94 03 33 6F FF 92 20 98 87 9C E5 B9 20 B5 68 DE 16 4A 15 C1 7F 72 71 65 3E A9 85 20 AF 5A 59 54 26 66 E9 3F 27 DE 8E 7D 34 53 61 F7 AF 09 29 5C F7 36 83 60 5F 52 92 5C D0 56 55 C9 61 7A FD EF 7E E8 70 F8 6E 7B EF }

condition:
		$a0 at entrypoint
}
	
	
rule EXEPACKv405v406
{
strings:
		$a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 06 ?? ?? 8E C0 8B 0E ?? ?? 8B F9 4F 8B F7 FD F3 A4 }

condition:
		$a0 at entrypoint
}
	
	
rule PECrypt32Consolev10v101v102
{
strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

condition:
		$a0 at entrypoint
}
	
	
rule EXEShieldv01bv03bv03SMoKE
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 }

condition:
		$a0 at entrypoint
}
	
	
rule BJFntv11b
{
strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv14x
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

condition:
		$a0
}
	
	
rule CICompress10
{
strings:
		$a0 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 }

condition:
		$a0
}
	
	
rule WATCOMCCRunTimesystemDOS4GWDOSExtender198893
{
strings:
		$a0 = { BF ?? ?? 8E D7 81 C4 ?? ?? BE ?? ?? 2B F7 8B C6 B1 ?? D3 }

condition:
		$a0 at entrypoint
}
	
	
rule PocketPCSHA
{
strings:
		$a0 = { 86 2F 96 2F A6 2F B6 2F 22 4F 43 68 53 6B 63 6A 73 69 F0 7F 0B D0 0B 40 09 00 09 D0 B3 65 A3 66 93 67 0B 40 83 64 03 64 04 D0 0B 40 09 00 10 7F 26 4F F6 6B F6 6A F6 69 0B 00 F6 68 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 22 4F F0 7F 0A D0 06 D4 06 D5 0B 40 09 }

condition:
		$a0 at entrypoint
}
	
	
rule PatchCreationWizard12SeekandDestroyPatch
{
strings:
		$a0 = { E8 C5 05 00 00 6A 00 E8 5E 05 00 00 A3 CE 39 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 72 05 00 00 6A 00 E8 2F 05 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 CE 39 40 00 E8 61 05 00 00 50 6A 01 68 80 00 00 00 FF 75 }

condition:
		$a0
}
	
	
rule TurboC301990
{
strings:
		$a0 = { 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B ?? ?? ?? 8E DA A3 ?? ?? 8C 06 }

condition:
		$a0 at entrypoint
}
	
	
rule bambamV004bedrock
{
strings:
		$a0 = { BF ?? ?? ?? ?? 83 C9 FF 33 C0 68 ?? ?? ?? ?? F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 11 0A 00 00 83 C4 0C 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F0 BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 BF ?? ?? ?? ?? 8B D1 68 ?? ?? ?? ?? C1 E9 02 F3 AB 8B CA 83 E1 03 F3 }

condition:
		$a0 at entrypoint
}
	
	
rule bambamV001bedrock
{
strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF }
	$a1 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF ?? ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule CrunchPEv40
{
strings:
		$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 E9 06 ?? ?? 89 85 E1 06 ?? ?? FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 03 00 00 89 85 D9 41 00 00 68 EC 49 7B 79 33 C0 50 E8 11 03 00 00 89 85 D1 41 00 00 E8 67 05 00 00 E9 56 05 00 00 51 52 53 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 5B 8B C2 C1 C0 10 66 8B C1 5A 59 C3 68 03 02 00 00 E8 80 04 00 00 0F 82 A8 02 00 00 96 8B 44 24 04 0F C8 8B D0 25 0F 0F 0F 0F 33 D0 C1 C0 08 0B C2 8B D0 25 33 33 33 33 33 D0 C1 C0 04 0B C2 8B D0 25 55 55 55 55 33 D0 C1 C0 02 0B C2 }

condition:
		$a0
}
	
	
rule DEFv10
{
strings:
		$a0 = { BE ?? 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 }
	$a1 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? 10 40 00 C3 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule UnnamedScrambler251Beta2252p0ke
{
strings:
		$a0 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? ?? 40 00 E8 ?? EA FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 BA ?? ?? 40 00 B8 ?? ?? 40 00 E8 63 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? ?? FF FF BA ?? ?? 40 00 8B C3 8B 0D ?? ?? 40 00 E8 }
	$a1 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? ?? 40 00 E8 ?? EA FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 BA ?? ?? 40 00 B8 ?? ?? 40 00 E8 63 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? ?? FF FF BA ?? ?? 40 00 8B C3 8B 0D ?? ?? 40 00 E8 ?? ?? FF FF C7 05 ?? ?? 40 00 0A 00 00 00 BB ?? ?? 40 00 BE ?? ?? 40 00 BF ?? ?? 40 00 B8 ?? ?? 40 00 BA 04 00 00 00 E8 ?? EB FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 0A F3 FF FF 89 03 83 3B 00 0F 84 F7 04 00 00 B8 ?? ?? 40 00 8B 16 E8 ?? E1 FF FF B8 ?? ?? 40 00 E8 ?? E0 FF FF 8B D0 8B 03 8B 0E E8 ?? ?? FF FF 8B C7 A3 ?? ?? 40 00 8D 55 EC 33 C0 E8 ?? D3 FF FF 8B 45 EC B9 ?? ?? 40 00 BA ?? ?? 40 00 E8 8B ED FF FF 3C 01 75 2B A1 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule eXPressorv13CGSoftLabsh
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 13 A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 ?? ?? E9 ?? ?? 00 00 C7 05 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv2001AlexeySolodovnikov
{
strings:
		$a0 = { 60 E8 72 05 00 00 EB 4C }

condition:
		$a0 at entrypoint
}
	
	
rule Crunchv40
{
strings:
		$a0 = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 03 00 00 89 85 D9 41 00 00 68 EC 49 7B 79 33 C0 50 E8 11 03 00 00 89 85 D1 41 00 00 E8 67 05 00 00 E9 56 05 00 00 51 52 53 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 5B 8B C2 C1 C0 10 66 8B C1 5A 59 C3 68 03 02 00 00 E8 80 04 00 00 0F 82 A8 02 00 00 96 8B 44 24 04 0F C8 8B D0 25 0F 0F 0F 0F 33 D0 C1 C0 08 0B C2 8B D0 25 33 33 33 33 33 D0 C1 C0 04 0B C2 8B D0 25 55 55 55 55 33 D0 C1 C0 02 0B C2 }

condition:
		$a0 at entrypoint
}
	
	
rule InstallShield3xCustom
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 00 A0 40 00 68 34 76 40 00 50 64 89 25 00 00 00 00 83 EC 60 53 56 57 89 65 E8 FF 15 8C E3 40 00 A3 70 B1 40 00 33 C0 A0 71 B1 40 00 A3 7C B1 40 00 A1 70 B1 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01FSG131Anorganix
{
strings:
		$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule StarForceProtectionDriverProtectionTechnologyh
{
strings:
		$a0 = { 57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule AVPAntiviralDatabase
{
strings:
		$a0 = { 41 56 50 20 41 6E 74 69 76 69 72 61 6C 20 44 61 74 61 62 61 73 65 }

condition:
		$a0
}
	
	
rule hmimyssPEPack01hmimys
{
strings:
		$a0 = { E8 00 00 00 00 5D 83 ED 05 6A 00 FF 95 E1 0E 00 00 89 85 85 0E 00 00 8B 58 3C 03 D8 81 C3 F8 00 00 00 80 AD 89 0E 00 00 01 89 9D 63 0F 00 00 8B 4B 0C 03 8D 85 0E 00 00 8B 53 08 80 BD 89 0E 00 00 00 75 0C 03 8D 91 0E 00 00 2B 95 91 0E 00 00 89 8D 57 0F 00 }
	$a1 = { E8 00 00 00 00 5D 83 ED 05 6A 00 FF 95 E1 0E 00 00 89 85 85 0E 00 00 8B 58 3C 03 D8 81 C3 F8 00 00 00 80 AD 89 0E 00 00 01 89 9D 63 0F 00 00 8B 4B 0C 03 8D 85 0E 00 00 8B 53 08 80 BD 89 0E 00 00 00 75 0C 03 8D 91 0E 00 00 2B 95 91 0E 00 00 89 8D 57 0F 00 00 89 95 5B 0F 00 00 8B 5B 10 89 9D 5F 0F 00 00 8B 9D 5F 0F 00 00 8B 85 57 0F 00 00 53 50 E8 B7 0B 00 00 89 85 73 0F 00 00 6A 04 68 00 10 00 00 50 6A 00 FF 95 E9 0E 00 00 89 85 6B 0F 00 00 6A 04 68 00 10 00 00 68 D8 7C 00 00 6A 00 FF 95 E9 0E 00 00 89 85 6F 0F 00 00 8D 85 67 0F 00 00 8B 9D 73 0F 00 00 8B 8D 6B 0F 00 00 8B 95 5B 0F 00 00 83 EA 0E 8B B5 57 0F 00 00 83 C6 0E 8B BD 6F 0F 00 00 50 53 51 52 56 68 D8 7C 00 00 57 E8 01 01 00 00 8B 9D 57 0F 00 00 8B 03 3C 01 75 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule NTkrnlSecureSuiteV01NTkrnlSoftwareSignbyfly
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 }

condition:
		$a0
}
	
	
rule PECompactv146
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12 }

condition:
		$a0 at entrypoint
}
	
	
rule EXEPACKLINKv360v364v365or50121
{
strings:
		$a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 50 B8 ?? ?? 50 CB }

condition:
		$a0 at entrypoint
}
	
	
rule PowerBASICWin800
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 14 04 00 00 E9 19 02 }

condition:
		$a0 at entrypoint
}
	
	
rule SpecialEXEPasswordProtectorv10
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoinerSmallbuild014015GlOFF
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 86 FF 68 00 01 00 00 68 F8 13 40 00 6A 00 E8 F3 01 00 00 8A C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 F8 13 40 00 E8 C9 01 00 00 A3 E0 13 40 00 40 0F 84 8B 01 00 00 90 90 90 90 90 6A 02 6A 00 6A FB FF 35 E0 13 40 00 E8 D1 01 00 00 86 FF 6A 00 8D 45 FC 50 6A 04 8D 45 F8 50 FF 35 E0 13 40 00 E8 B2 01 00 00 8A C0 6A 00 8D 45 FC 50 6A 01 8D 45 F3 50 }
	$a1 = { E8 0E FE FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule MicrosoftVisualC
{
strings:
		$a0 = { 83 ?? ?? 6A 00 FF 15 F8 10 0B B0 8D ?? ?? ?? 51 6A 08 6A 00 6A 00 68 }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 }
	$a2 = { 8B 44 24 08 56 83 E8 ?? 74 ?? 48 75 }
	$a3 = { 8B 44 24 08 83 ?? ?? 74 }

condition:
		$a0 at entrypoint or $a1 or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule ExeJoiner10Yoda
{
strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 E8 E2 02 00 00 83 F8 FF 0F 84 6D 02 00 00 A3 0C 12 40 00 8B D8 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 E3 02 00 00 6A 00 68 3C 12 40 00 6A 04 68 1E 12 40 00 FF 35 08 12 40 00 E8 C4 02 00 00 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule muckisprotectormucki
{
strings:
		$a0 = { BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule CrypKeyV56XKenonicControlsLtd
{
strings:
		$a0 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule Safe20
{
strings:
		$a0 = { 83 EC 10 53 56 57 E8 C4 01 00 }

condition:
		$a0
}
	
	
rule MicrosoftVisualCV80
{
strings:
		$a0 = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8 }

condition:
		$a0 at entrypoint
}
	
	
rule MZ_Crypt10byBrainSt0rm
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 25 14 40 00 8B BD 77 14 40 00 8B 8D 7F 14 40 00 EB 28 83 7F 1C 07 75 1E 8B 77 0C 03 B5 7B 14 40 00 33 C0 EB 0C 50 8A A5 83 14 40 00 30 26 58 40 46 3B 47 10 76 EF 83 C7 28 49 0B C9 75 D4 8B 85 73 14 40 00 89 44 24 1C 61 FF E0 }

condition:
		$a0 at entrypoint
}
	
	
rule EPWv130
{
strings:
		$a0 = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E }

condition:
		$a0 at entrypoint
}
	
	
rule WindofCrypt10byDarkPressure
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 64 40 00 10 E8 28 EA FF FF 33 C0 55 68 CE 51 00 10 64 ?? ?? ?? ?? 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 F6 DB FF FF 8B 45 EC E8 12 E7 FF FF 50 E8 3C EA FF FF 8B D8 83 FB FF }
	$a1 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 64 40 00 10 E8 28 EA FF FF 33 C0 55 68 CE 51 00 10 64 ?? ?? ?? ?? 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 F6 DB FF FF 8B 45 EC E8 12 E7 FF FF 50 E8 3C EA FF FF 8B D8 83 FB FF 0F 84 A6 00 00 00 6A 00 53 E8 41 EA FF FF 8B F0 81 EE 00 5E 00 00 6A 00 6A 00 68 00 5E 00 00 53 E8 52 EA FF FF B8 F4 97 00 10 8B D6 E8 2E E7 FF FF B8 F8 97 00 10 8B D6 E8 22 E7 FF FF 8B C6 E8 AB D8 FF FF 8B F8 6A 00 68 F0 97 00 10 56 A1 F4 97 00 10 50 53 E8 05 EA FF FF 53 E8 CF E9 FF FF B8 FC 97 00 10 BA E8 51 00 10 E8 74 EA FF FF A1 F4 97 00 10 85 C0 74 05 83 E8 04 8B 00 50 B9 F8 97 00 10 B8 FC 97 00 10 8B 15 F4 97 00 10 E8 D8 EA FF FF B8 FC 97 00 10 E8 5A EB FF FF 8B CE 8B 15 F8 97 00 10 8B C7 E8 EB E9 FF FF 8B C7 85 C0 74 05 E8 E4 EB FF FF 33 C0 5A 59 59 64 89 10 68 D5 51 00 10 8D 45 EC E8 BB E5 FF FF C3 E9 A9 DF FF FF EB F0 5F 5E 5B E8 B7 E4 FF FF 00 00 00 FF FF FF FF 0A 00 00 00 63 5A 6C 56 30 55 6C 6B 70 4D }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MicrosoftVisualBasicv60DLL
{
strings:
		$a0 = { 5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv71DLL
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? 40 00 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 E4 53 56 57 89 65 E8 C7 45 E4 01 00 00 00 C7 45 FC }
	$a2 = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 }
	$a3 = { 83 7C 24 08 01 75 ?? ?? ?? 24 04 50 A3 ?? ?? ?? 50 FF 15 00 10 ?? 50 33 C0 40 C2 0C 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule CrackedbyAutohack2
{
strings:
		$a0 = { 0E 1F B4 09 BA ?? ?? CD 21 FA 8E 06 ?? ?? BE ?? ?? 8B 0E ?? ?? 83 F9 }

condition:
		$a0 at entrypoint
}
	
	
rule NTKrnlPackerAshkbizDanehkar
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }

condition:
		$a0
}
	
	
rule MSVisualCv8hgoodsigbutisitMSVC
{
strings:
		$a0 = { E8 ?? ?? ?? ?? E9 8D FE FF FF CC CC CC CC CC 66 81 3D 00 00 00 01 4D 5A 74 04 33 C0 EB 51 A1 3C 00 00 01 81 B8 00 00 00 01 50 45 00 00 75 EB 0F B7 88 18 00 00 01 81 F9 0B 01 00 00 74 1B 81 F9 0B 02 00 00 75 D4 83 B8 84 00 00 01 0E 76 CB 33 C9 39 88 F8 00 }
	$a1 = { E8 ?? ?? ?? ?? E9 8D FE FF FF CC CC CC CC CC 66 81 3D 00 00 00 01 4D 5A 74 04 33 C0 EB 51 A1 3C 00 00 01 81 B8 00 00 00 01 50 45 00 00 75 EB 0F B7 88 18 00 00 01 81 F9 0B 01 00 00 74 1B 81 F9 0B 02 00 00 75 D4 83 B8 84 00 00 01 0E 76 CB 33 C9 39 88 F8 00 00 01 EB 11 83 B8 74 00 00 01 0E 76 B8 33 C9 39 88 E8 00 00 01 0F 95 C1 8B C1 6A 01 A3 ?? ?? ?? 01 E8 ?? ?? 00 00 50 FF ?? ?? ?? 00 01 83 0D ?? ?? ?? 01 FF 83 0D ?? ?? ?? 01 FF 59 59 FF 15 ?? ?? 00 01 8B 0D ?? ?? ?? 01 89 08 FF 15 ?? ?? 00 01 8B 0D ?? ?? ?? 01 89 08 A1 ?? ?? 00 01 8B 00 A3 ?? ?? ?? 01 E8 ?? ?? 00 00 83 3D ?? ?? ?? 01 00 75 0C 68 ?? ?? ?? 01 FF 15 ?? ?? 00 01 59 E8 ?? ?? 00 00 33 C0 C3 CC CC CC CC CC }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule PseudoSigner01LCCWin321xAnorganix
{
strings:
		$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorv14CGSoftLabsh
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8 }

condition:
		$a0 at entrypoint
}
	
	
rule NME11Publicbyredlime
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 30 35 14 13 E8 9A E6 FF FF 33 C0 55 68 6C 36 14 13 64 FF 30 64 89 20 B8 08 5C 14 13 BA 84 36 14 13 E8 7D E2 FF FF E8 C0 EA FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 04 F8 FF FF 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 F4 F7 FF FF 8B }
	$a1 = { 55 8B EC 83 C4 F0 53 56 B8 30 35 14 13 E8 9A E6 FF FF 33 C0 55 68 6C 36 14 13 64 FF 30 64 89 20 B8 08 5C 14 13 BA 84 36 14 13 E8 7D E2 FF FF E8 C0 EA FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 04 F8 FF FF 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 F4 F7 FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 2C F9 FF FF A3 F8 5A 14 13 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 17 F9 FF FF A3 FC 5A 14 13 B8 04 5C 14 13 E8 20 FB FF FF 8B D8 85 DB 74 48 B8 00 5B 14 13 8B 15 C4 45 14 13 E8 1E E7 FF FF A1 04 5C 14 13 E8 A8 DA FF FF ?? ?? ?? ?? 5C 14 13 50 8B CE 8B D3 B8 00 5B 14 13 ?? ?? ?? ?? FF 8B C6 E8 DF FB FF FF 8B C6 E8 9C DA FF FF B8 00 5B 14 13 E8 72 E7 FF FF 33 C0 5A 59 59 64 89 10 68 73 36 14 13 C3 E9 0F DF FF FF EB F8 5E 5B E8 7E E0 FF FF 00 00 FF FF FF FF 0C 00 00 00 4E 4D 45 20 31 2E 31 20 53 74 75 62 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PseudoSigner02LCCWin321x
{
strings:
		$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 }

condition:
		$a0 at entrypoint
}
	
	
rule PEtitev13
{
strings:
		$a0 = { 66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }

condition:
		$a0 at entrypoint
}
	
	
rule PEtitev12
{
strings:
		$a0 = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02ASProtect
{
strings:
		$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv134v140b1
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 00 80 ?? 40 90 90 01 85 9E 80 ?? 40 BB F8 10 }

condition:
		$a0 at entrypoint
}
	
	
rule PEtitev14
{
strings:
		$a0 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }
	$a1 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule eXPressor12CGSoftLabsh
{
strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? ?? 2B 05 84 ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 16 A1 ?? ?? ?? ?? 03 05 80 ?? ?? ?? 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 68 04 }

condition:
		$a0
}
	
	
rule TXT2COMv206
{
strings:
		$a0 = { 8D 26 ?? ?? E8 ?? ?? B8 ?? ?? CD 21 CD 20 54 58 54 32 43 4F 4D 20 }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePackV11XMethod2bagieSignbyfly
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 }

condition:
		$a0
}
	
	
rule Unknownencryptor1
{
strings:
		$a0 = { EB ?? 2E 90 ?? ?? 8C DB 8C CA 8E DA FA 8B EC BE ?? ?? BC ?? ?? BF }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack118LZMA430ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule PESHiELDv025
{
strings:
		$a0 = { 60 E8 2B 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ARMProtector01bySMoKE
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 }

condition:
		$a0
}
	
	
rule tElock099cPrivateECLIPSEtE
{
strings:
		$a0 = { E9 3F DF FF FF 00 00 00 ?? ?? ?? ?? 04 ?? ?? 00 00 00 00 00 00 00 00 00 24 ?? ?? 00 14 ?? ?? 00 0C ?? ?? 00 00 00 00 00 00 00 00 00 31 ?? ?? 00 1C ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

condition:
		$a0 at entrypoint
}
	
	
rule XPack152164
{
strings:
		$a0 = { 8B EC FA 33 C0 8E D0 BC ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov253b3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }

condition:
		$a0 at entrypoint
}
	
	
rule aPackv098bcom
{
strings:
		$a0 = { BE ?? ?? BF ?? ?? 8B CF FC 57 F3 A4 C3 BF ?? ?? 57 57 BE ?? ?? B2 ?? BD ?? ?? 50 A4 }

condition:
		$a0
}
	
	
rule PrivateexeProtectorV18XV19XSetiSoftTeam
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

condition:
		$a0
}
	
	
rule PEiDBundlev100v101BoBBobSoft
{
strings:
		$a0 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

condition:
		$a0 at entrypoint
}
	
	
rule nPackV111502006BetaNEOxuinC
{
strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }
	$a1 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 56 57 68 54 ?? ?? ?? FF 15 00 ?? ?? ?? 8B 35 08 ?? ?? ?? 8B F8 68 44 ?? ?? ?? 57 FF D6 68 38 ?? ?? ?? 57 A3 38 ?? ?? ?? FF D6 5F A3 34 ?? ?? ?? 5E C3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Alloy4xPGWareLLC
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68 }
	$a1 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68 D8 01 00 00 50 FF 95 CC 33 40 00 50 8D 85 28 33 40 00 50 FF B5 2E 33 40 00 FF 95 D0 33 40 00 58 83 C0 05 EB 0C 68 D8 01 00 00 50 FF 95 C0 33 40 00 8B BD 2E 33 40 00 03 F8 C6 07 5C 47 8D B5 00 33 40 00 AC 0A C0 74 03 AA EB F8 83 BD DC 32 40 00 01 74 7A 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 FF B5 2E 33 40 00 FF 95 B4 33 40 00 83 F8 FF 74 57 89 85 32 33 40 00 8D 85 56 33 40 00 8D 9D 5E 33 40 00 8D 8D 66 33 40 00 51 53 50 FF B5 32 33 40 00 FF 95 C4 33 40 00 FF B5 32 33 40 00 FF 95 B8 33 40 00 8B 85 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ThinstallV2403Jitit
{
strings:
		$a0 = { 6A 00 FF 15 20 50 40 00 E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 57 BF 00 00 80 00 39 79 14 77 36 53 56 8B B1 29 04 00 00 8B 41 0C 8B 59 10 03 DB 8A 14 30 83 E2 01 0B D3 C1 E2 07 40 89 51 10 89 41 0C 0F B6 04 30 C1 61 14 08 D1 E8 09 41 10 39 }

condition:
		$a0 at entrypoint
}
	
	
rule FSG131Engdulekxt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }

condition:
		$a0
}
	
	
rule FakeNinjav28AntiDebugSpirit
{
strings:
		$a0 = { 64 A1 18 00 00 00 EB 02 C3 11 8B 40 30 EB 01 0F 0F B6 40 02 83 F8 01 74 FE EB 01 E8 90 C0 FF FF EB 03 BD F4 B5 64 A1 30 00 00 00 0F B6 40 02 74 01 BA 74 E0 50 00 64 A1 30 00 00 00 83 C0 68 8B 00 EB 00 83 F8 70 74 CF EB 02 EB FE 90 90 90 0F 31 33 C9 03 C8 0F 31 2B C1 3D FF 0F 00 00 73 EA E8 08 00 00 00 C1 3D FF 0F 00 00 74 AA EB 07 E8 8B 40 30 EB 08 EA 64 A1 18 00 00 00 EB F2 90 90 90 BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 11 00 00 6A 00 6A 00 FF 35 70 11 40 00 FF 35 84 11 40 00 E8 25 11 00 00 FF }

condition:
		$a0
}
	
	
rule GHFProtectorpackGPcH
{
strings:
		$a0 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 A0 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeLockv100
{
strings:
		$a0 = { 06 8C C8 8E C0 BE ?? ?? 26 ?? ?? 34 ?? 26 ?? ?? 46 81 ?? ?? ?? 75 ?? 40 B3 ?? B3 ?? F3 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor16byVaskaDamraisign200320072041
{
strings:
		$a0 = { 33 D0 68 40 A1 14 13 FF D2 B8 00 10 14 13 3D 24 C0 14 13 74 06 80 30 BB 40 EB F3 33 C0 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv30DLL_LZMAMarkusOberhumerLaszloMolnarJohnReiser
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 C7 0B 00 00 60 BE 00 ?? ?? ?? 8D BE 00 ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ENIGMAProtectorV1XSukhovVladimir
{
strings:
		$a0 = { 45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31 }

condition:
		$a0
}
	
	
rule PseudoSigner02MEW11SE10
{
strings:
		$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }

condition:
		$a0 at entrypoint
}
	
	
rule AVImoviefile
{
strings:
		$a0 = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 ?? 4C 49 53 54 }

condition:
		$a0
}
	
	
rule MicrosoftCABSFXmodule
{
strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20 }

condition:
		$a0 at entrypoint
}
	
	
rule VProtectorV11AV12vcasm
{
strings:
		$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F 32 30 30 35 5F 33 5F 31 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule tElock09910privatetE
{
strings:
		$a0 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule AHpack01FEUERRADERh
{
strings:
		$a0 = { 60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallVirtualizationSuiteV3049V3080ThinstallCompanySignbyfly
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtectorV1033AshkbizDanehkarSignbyfly
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 }

condition:
		$a0 at entrypoint
}
	
	
rule AVPInspectorDatabase
{
strings:
		$a0 = { 47 68 6F 73 74 20 42 75 73 74 65 72 }

condition:
		$a0
}
	
	
rule BorlandDelphiv60
{
strings:
		$a0 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 }
	$a1 = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PCPECalpha
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ?? ?? ?? ?? ?? 2B ?? ?? ?? ?? ?? 83 }

condition:
		$a0 at entrypoint
}
	
	
rule PEProtect09byCristophGabler1998
{
strings:
		$a0 = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }

condition:
		$a0
}
	
	
rule VxPredator2448
{
strings:
		$a0 = { 0E 1F BF ?? ?? B8 ?? ?? B9 ?? ?? 49 ?? ?? ?? ?? 2A C1 4F 4F ?? ?? F9 CC }

condition:
		$a0 at entrypoint
}
	
	
rule TurboC
{
strings:
		$a0 = { BC ?? ?? E8 ?? ?? 2E 8E ?? ?? ?? E8 ?? ?? 2E 80 ?? ?? ?? ?? 75 ?? E8 ?? ?? 8B C3 2E F7 ?? ?? ?? E8 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv16dVaska
{
strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
	$a1 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule hyingsPEArmorV076hying
{
strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VBOXv43MTE
{
strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorv12CGSoftLabsh
{
strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? ?? 2B 05 84 ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 16 A1 ?? ?? ?? ?? 03 05 80 ?? ?? ?? 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 }

condition:
		$a0 at entrypoint
}
	
	
rule JDPackV200JDPack
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? 05 00 00 00 00 83 C4 0C 5D 60 E8 00 00 00 00 5D 8B D5 64 FF 35 00 00 00 00 EB }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv01xv02xDwing
{
strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 }

condition:
		$a0 at entrypoint
}
	
	
rule VcasmProtectorV1Xvcasm
{
strings:
		$a0 = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D }

condition:
		$a0 at entrypoint
}
	
	
rule LTCv13
{
strings:
		$a0 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv42DLL
{
strings:
		$a0 = { 53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75 }

condition:
		$a0 at entrypoint
}
	
	
rule kkrunchy023alpha2Ryd
{
strings:
		$a0 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
	$a1 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF ?? ?? ?? 01 31 C9 41 8D 74 09 01 B8 CA 8E 2A 2E 99 F7 F6 01 C3 89 D8 C1 E8 15 AB FE C1 75 E8 BE }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PolyEnEV001LennartHedlund
{
strings:
		$a0 = { 50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C }

condition:
		$a0
}
	
	
rule Winkriptv10
{
strings:
		$a0 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }

condition:
		$a0 at entrypoint
}
	
	
rule CICryptV02FearlesS
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 }

condition:
		$a0 at entrypoint
}
	
	
rule TrainerCreationKitv5Trainer
{
strings:
		$a0 = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 00 68 34 45 40 00 50 E8 15 02 00 00 6A 00 FF 35 30 45 40 00 50 6A 02 E8 4D 02 00 00 A3 74 45 40 00 6A 00 68 D4 10 40 00 6A 00 6A 01 FF 35 70 45 40 00 E8 02 02 00 00 B3 0A FE CB 74 10 FF 35 74 45 40 00 E8 27 02 00 00 83 F8 00 74 EC B3 0A FE CB 74 10 FF 35 30 45 40 00 E8 B7 01 00 00 83 F8 00 74 EC B3 0A FE CB 74 16 68 25 45 40 00 E8 96 01 00 00 83 F8 00 74 ED 6A 00 E8 90 01 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C7 00 00 00 6A 01 FF 35 70 45 40 00 E8 B0 01 00 00 50 6A 01 68 80 00 00 00 FF }

condition:
		$a0
}
	
	
rule EXEStealthv272
{
strings:
		$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealthv271
{
strings:
		$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40 }

condition:
		$a0 at entrypoint
}
	
	
rule AHpack01FEUERRADER
{
strings:
		$a0 = { 60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSafeguard10simonzhh
{
strings:
		$a0 = { C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE }

condition:
		$a0
}
	
	
	
rule ProtectSharewareV11eCompservCMS
{
strings:
		$a0 = { 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 ?? 01 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 34 00 ?? 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 00 4A 00 76 00 77 00 }

condition:
		$a0
}
	
	
rule ASPackv10801AlexeySolodovnikov
{
strings:
		$a0 = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule DZAPatcherv13DZA
{
strings:
		$a0 = { EB 08 35 48 34 30 4C 31 4E 00 60 E8 00 00 00 00 5D 8B D5 81 ED 44 73 40 00 2B 95 74 74 40 00 83 EA 10 89 95 70 74 40 00 8B 44 24 20 25 00 00 FF FF 80 38 4D 74 07 2D 00 00 01 00 EB F4 93 89 85 7C 74 40 00 8D BD 8C 74 40 00 E8 83 00 00 00 89 85 80 74 40 00 }
	$a1 = { EB 08 35 48 34 30 4C 31 4E 00 60 E8 00 00 00 00 5D 8B D5 81 ED 44 73 40 00 2B 95 74 74 40 00 83 EA 10 89 95 70 74 40 00 8B 44 24 20 25 00 00 FF FF 80 38 4D 74 07 2D 00 00 01 00 EB F4 93 89 85 7C 74 40 00 8D BD 8C 74 40 00 E8 83 00 00 00 89 85 80 74 40 00 8D BD A4 74 40 00 E8 72 00 00 00 89 85 84 74 40 00 8D BD F0 73 40 00 57 FF D0 8D BD 99 74 40 00 E8 58 00 00 00 89 85 88 74 40 00 8B 85 78 74 40 00 03 85 70 74 40 00 99 8D 8D 6C 74 40 00 51 52 52 50 52 52 FF 95 80 74 40 00 8D BD C0 74 40 00 8B 0F E3 13 8A 5F 05 8A 01 3A C3 75 FA 8A 57 04 88 11 83 C7 06 EB E9 E8 00 00 00 00 5D 81 ED F5 73 40 00 6A 00 FF 95 88 74 40 00 61 C3 8B D3 0F B7 43 3C 03 D8 8B 5B 78 03 DA 0B FF 74 40 8B 73 20 03 F2 8B 4B 18 53 33 DB AD 03 C2 56 57 87 FE 97 AC 0A C0 75 07 80 3F 00 74 0B }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ENIGMAProtectorV11SukhovVladimir
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect123RC4build0807exeAlexeySolodovnikovh
{
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule SimbiOZExtranger
{
strings:
		$a0 = { 50 60 E8 00 00 00 00 5D 81 ED 07 10 40 00 68 80 0B 00 00 8D 85 1F 10 40 00 50 E8 84 0B 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule InnoSetupModulev304betav306v307
{
strings:
		$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

condition:
		$a0
}
	
	
rule BorlandPascalv70forWindows
{
strings:
		$a0 = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2021wwwstrongbitcomSignByhaggar
{
strings:
		$a0 = { 55 8B EC 83 C4 F4 56 57 53 BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 D0 03 45 F4 8B 18 8B 7E 10 01 D7 03 7D F4 09 DB 0F 84 ?? 00 00 00 F7 C3 00 00 00 80 0F 85 04 00 00 00 8D 5C 13 02 81 E3 FF FF FF ?? 53 FF 75 F8 FF 15 9C ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 07 83 45 F4 04 E9 A6 FF FF FF }

condition:
		$a0
}
	
	
rule AutoDeskAnimationfile
{
strings:
		$a0 = { 00 12 AF ?? ?? 40 01 C8 }

condition:
		$a0
}
	
	
rule HACKSTOPv110p1
{
strings:
		$a0 = { B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 ?? ?? 58 EB }

condition:
		$a0 at entrypoint
}
	
	
rule AdysGlue110
{
strings:
		$a0 = { 2E ?? ?? ?? ?? 0E 1F BF ?? ?? 33 DB 33 C0 AC }

condition:
		$a0 at entrypoint
}
	
	
rule VxEddiebased1745
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA ?? 8B E6 81 ?? ?? ?? FB ?? 3B ?? ?? ?? ?? ?? 50 06 ?? 56 1E 8B FE 33 C0 ?? 50 8E D8 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv107b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
	$a1 = { 90 90 90 75 ?? E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MSRunTimeLibraryOS2FORTRANCompiler1989
{
strings:
		$a0 = { B4 30 CD 21 86 E0 2E A3 ?? ?? 3D ?? ?? 73 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv100
{
strings:
		$a0 = { E9 E5 E2 FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule ASDPackv10asd
{
strings:
		$a0 = { 55 8B EC 56 53 E8 5C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 ?? ?? ?? 00 00 00 00 00 00 00 40 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 ?? 00 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5B 81 EB E6 1D 40 00 83 7D 0C 01 75 11 55 E8 4F 01 00 00 E8 6A 01 00 00 5D E8 2C 00 00 00 8B B3 1A 1E 40 00 03 B3 FA 1D 40 00 8B 76 0C AD 0B C0 74 0D FF 75 10 FF 75 0C FF 75 08 FF D0 EB EE B8 01 00 00 00 5B 5E C9 C2 0C 00 55 6A 00 FF 93 20 21 40 00 89 83 FA 1D 40 00 6A 40 68 00 10 00 00 FF B3 02 1E 40 00 6A 00 FF 93 2C 21 40 00 89 83 06 1E 40 00 8B 83 F2 1D 40 00 03 83 FA 1D 40 00 50 FF B3 06 1E 40 00 50 E8 6D 01 00 00 5F }

condition:
		$a0
}
	
	
rule ASProtect20
{
strings:
		$a0 = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }

condition:
		$a0
}
	
	
rule Crunch5Fusion4BitArts
{
strings:
		$a0 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule StonesPEEncryptorv113
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }

condition:
		$a0 at entrypoint
}
	
	
rule SexeCrypter11bysantasdad
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 D8 39 00 10 E8 30 FA FF FF 33 C0 55 68 D4 3A 00 10 64 FF 30 64 89 ?? ?? ?? ?? E4 3A 00 10 A1 00 57 00 10 50 E8 CC FA FF FF 8B D8 53 A1 00 57 00 10 50 E8 FE FA FF FF 8B F8 53 A1 00 57 00 10 50 E8 C8 FA FF FF 8B D8 53 E8 C8 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 14 57 00 10 E8 AD F6 FF FF B8 14 57 00 10 E8 9B F6 FF FF 8B CF 8B D6 E8 DA FA FF FF 53 E8 84 FA FF FF 8D 4D EC BA F8 3A 00 10 A1 14 57 00 10 E8 0A FB FF FF 8B 55 EC B8 14 57 00 10 E8 65 F5 FF FF B8 14 57 00 10 E8 63 F6 FF FF E8 52 FC FF FF 33 C0 5A 59 59 64 89 10 68 DB 3A 00 10 8D 45 EC E8 ED F4 FF FF C3 E9 83 EF FF FF EB F0 5F 5E 5B E8 ED F3 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 12 00 00 00 6B 75 74 68 37 36 67 62 62 67 36 37 34 76 38 38 67 79 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv302v302aExtractable
{
strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule ARMProtector03bySMoKE
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 13 24 40 00 EB 02 83 09 8D B5 A4 24 40 00 EB 02 83 09 BA 4B 15 00 00 EB 01 00 8D 8D EF 39 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }

condition:
		$a0
}
	
	
rule VxSlowload
{
strings:
		$a0 = { 03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01 }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote10BetaSISTeam
{
strings:
		$a0 = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 66 8B 41 06 89 54 24 14 8D 68 FF 85 ED 7C 37 33 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule DzAPatcherv13Loader
{
strings:
		$a0 = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 48 20 40 00 E8 C2 00 00 00 E8 C8 FF FF FF BF 40 40 40 00 FF 35 4C 20 40 00 E8 A1 00 00 00 8B 0F 83 F9 00 74 B1 60 6A 00 6A 04 6A 01 51 FF 35 48 20 40 00 E8 75 00 00 00 61 60 BB 5C 20 40 00 6A 00 6A 01 53 51 FF 35 48 20 40 00 E8 75 00 00 00 61 A0 5C 20 40 00 8A 5F 05 3A C3 74 14 FF 35 4C 20 40 00 E8 4B 00 00 00 6A 03 E8 4A 00 00 00 EB A2 60 8D 5F 04 6A 00 6A 01 53 51 FF 35 48 20 40 00 E8 4B 00 00 00 61 83 C7 06 FF 35 4C 20 40 00 E8 1E 00 00 00 6A 03 E8 1D 00 00 00 E9 72 FF FF FF FF 25 70 30 40 00 FF 25 78 }

condition:
		$a0
}
	
	
rule NTPackerV2XErazerZSignbyfly
{
strings:
		$a0 = { 4B 57 69 6E 64 6F 77 73 00 10 55 54 79 70 65 73 00 00 3F 75 6E 74 4D 61 69 6E 46 75 6E 63 74 69 6F 6E 73 00 00 47 75 6E 74 42 79 70 61 73 73 00 00 B7 61 50 4C 69 62 75 00 00 00 }

condition:
		$a0
}
	
	
rule CDSSS10beta1CyberDoom
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 4E 40 00 E8 D7 03 00 00 0B C0 0F 84 A9 02 00 00 E8 F9 02 00 00 89 85 94 4E 40 00 8D 85 12 4D 40 00 50 }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystem20b4
{
strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }
	$a1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 }

condition:
		$a0 or $a1
}
	
	
rule EncryptPEV22004616V22006630WFSSignbyfly
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule y0dasCrypterv11
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftPiMPInstallSystemv1x
{
strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 3E 2F }

condition:
		$a0
}
	
	
rule BlindSpot10s134k
{
strings:
		$a0 = { 55 8B EC 81 EC 50 02 00 00 8D 85 B0 FE FF FF 53 56 A3 90 12 40 00 57 8D 85 B0 FD FF FF 68 00 01 00 00 33 F6 50 56 FF 15 24 10 40 00 56 68 80 00 00 00 6A 03 56 56 8D 85 B0 FD FF FF 68 00 00 00 80 50 FF 15 20 10 40 00 56 56 68 00 08 00 00 50 89 45 FC FF 15 }
	$a1 = { 55 8B EC 81 EC 50 02 00 00 8D 85 B0 FE FF FF 53 56 A3 90 12 40 00 57 8D 85 B0 FD FF FF 68 00 01 00 00 33 F6 50 56 FF 15 24 10 40 00 56 68 80 00 00 00 6A 03 56 56 8D 85 B0 FD FF FF 68 00 00 00 80 50 FF 15 20 10 40 00 56 56 68 00 08 00 00 50 89 45 FC FF 15 1C 10 40 00 8D 45 F8 8B 1D 18 10 40 00 56 50 6A 34 FF 35 90 12 40 00 FF 75 FC FF D3 85 C0 0F 84 7F 01 00 00 39 75 F8 0F 84 76 01 00 00 A1 90 12 40 00 66 8B 40 30 66 3D 01 00 75 14 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 14 10 40 00 EB 2C 66 3D 02 00 75 14 8D 85 E4 FE FF FF 50 68 04 01 00 00 FF 15 10 10 40 00 EB 12 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 0C 10 40 00 8B 3D 08 10 40 00 8D 85 E4 FE FF FF 68 54 10 40 00 50 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ExeBundlev30smallloader
{
strings:
		$a0 = { 00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXAlternativestub
{
strings:
		$a0 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }

condition:
		$a0 at entrypoint
}
	
	
rule EmbedPE113cyclotron
{
strings:
		$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 }
	$a1 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33 }
	$a2 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33 A3 F5 0B 85 97 7C BA 1D 96 DD 07 F8 FD D2 3A 98 83 CC 46 99 9D DF 6F 89 92 54 46 9F 94 43 CC 41 43 9B 8C 61 B9 D8 6F 96 3B D1 07 32 24 DD 07 05 8E CB 6F A1 07 5C 62 20 E0 DB BA 9D 83 54 46 E6 83 51 7A 2B 94 54 64 8A 83 05 68 D7 5E 2D C6 B7 57 00 B3 E8 3C 71 B8 3C 97 7C 36 19 32 7C 08 2A 06 51 64 73 A3 F1 4E 92 25 CB 80 8D 99 54 46 B0 E1 D3 46 A5 2D 10 68 B6 83 91 46 F2 DF 64 FD D1 BC CA AA 70 E2 AB 39 AE 3B 5A 6F 9B 15 BD 25 98 25 30 4C AD 7D 55 07 A8 A3 AC 0A C1 BD 54 72 BC 83 54 82 A3 97 B1 1A B3 83 54 46 83 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule PseudoSigner01Armadillo300Anorganix
{
strings:
		$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptorvxxxx
{
strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 }

condition:
		$a0 at entrypoint
}
	
	
rule PatchCreationWizardv12MemoryPatch
{
strings:
		$a0 = { 6A 00 E8 9B 02 00 00 A3 7A 33 40 00 6A 00 68 8E 10 40 00 6A 00 6A 01 50 E8 B5 02 00 00 68 5A 31 40 00 68 12 31 40 00 6A 00 6A 00 6A 04 6A 01 6A 00 6A 00 68 A2 30 40 00 6A 00 E8 51 02 00 00 85 C0 74 31 FF 35 62 31 40 00 6A 00 6A 30 E8 62 02 00 00 E8 0B 01 00 00 FF 35 5A 31 40 00 E8 22 02 00 00 FF 35 5E 31 40 00 E8 53 02 00 00 6A 00 E8 22 02 00 00 6A 10 68 F7 30 40 00 68 FE 30 40 00 6A 00 E8 63 02 00 00 6A 00 E8 08 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 75 6B 6A 01 FF 35 7A 33 40 00 E8 38 02 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 34 02 00 00 68 00 30 40 00 6A 65 FF 75 08 E8 2B 02 00 00 68 51 30 40 00 6A 67 FF 75 08 E8 1C 02 00 00 68 A2 30 40 00 6A 66 FF 75 08 E8 0D 02 00 00 8B 45 08 A3 7E 33 40 00 68 3B 11 40 00 68 E8 03 00 00 68 9A 02 00 }

condition:
		$a0
}
	
	
rule DEF10bartxt
{
strings:
		$a0 = { BE ?? ?? 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a1 = { BE ?? ?? 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PECompactv0971v0976
{
strings:
		$a0 = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }

condition:
		$a0 at entrypoint
}
	
	
rule Unknownencryptor2PK7Tjrvx
{
strings:
		$a0 = { 06 B4 52 CD 21 07 E8 ?? ?? B4 62 CD 21 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule PocketPCARMh
{
strings:
		$a0 = { F0 41 2D E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 50 E3 ?? 00 00 0A ?? ?? ?? ?? ?? ?? A0 ?? ?? ?? ?? ?? ?? ?? A0 ?? ?? ?? A0 E1 00 80 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A0 E1 }

condition:
		$a0 at entrypoint
}
	
	
rule PCShrinkv040b
{
strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv70BasicNET
{
strings:
		$a0 = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule PESpin07Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

condition:
		$a0
}
	
	
rule MSLRHv032afakePELockNT204emadiciush
{
strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 EB EB 03 CD 20 03 61 9D 83 C4 04 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallVirtualizationSuite30xxJititSoftware
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 00 00 00 01 68 00 ?? 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 }

condition:
		$a0 at entrypoint
}
	
	
rule ORiENv211212FisunAlexander
{
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE ?? 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D 20 2D 0D 0A 2D 2D 2D 2D 2D 2D 20 43 72 65 61 74 65 64 20 62 79 20 41 2E 20 46 69 73 75 6E 2C 20 31 39 39 34 2D 32 30 30 33 20 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 20 57 57 57 3A 20 68 74 74 70 3A 2F 2F 7A 61 6C 65 78 66 2E 6E 61 72 6F 64 2E 72 75 2F 20 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 20 65 2D 6D 61 69 6C 3A 20 7A 61 6C 65 78 66 40 68 6F 74 6D 61 69 6C 2E 72 75 20 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D }

condition:
		$a0 at entrypoint
}
	
	
rule StonesPEEncruptorv113
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 }

condition:
		$a0 at entrypoint
}
	
	
rule FreePascal200Win32BercziGaborPierreMullerPeterVreman
{
strings:
		$a0 = { 55 89 E5 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 6A 00 64 FF 35 00 00 00 00 89 E0 A3 ?? ?? ?? ?? 55 31 ED 89 E0 A3 ?? ?? ?? ?? 66 8C D5 89 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? 5D E8 ?? ?? ?? ?? C9 C3 }
	$a1 = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 00 E8 C5 01 00 00 89 D8 E8 3E 02 00 00 E8 B9 01 00 00 E8 54 02 00 00 8B 5D FC C9 C3 8D 76 00 00 00 00 00 00 00 00 00 00 00 00 00 55 89 E5 C6 05 10 80 40 00 00 E8 D1 03 00 00 6A 00 64 FF 35 00 00 00 00 89 E0 A3 ?? 70 40 00 55 31 ED 89 E0 A3 20 80 40 00 66 8C D5 89 2D 30 80 40 00 E8 B9 03 00 00 31 ED E8 72 FF FF FF 5D E8 BC 03 00 00 C9 C3 00 00 00 00 00 00 00 00 00 00 55 89 E5 83 EC 08 E8 15 04 00 00 A1 ?? 70 40 00 89 45 F8 B8 01 00 00 00 89 45 FC 3B 45 F8 7F 2A FF 4D FC 90 FF 45 FC 8B 45 FC 83 3C C5 ?? 70 40 00 00 74 09 8B 04 C5 ?? 70 40 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule ANDpakk2006byDmitryANDAndreev
{
strings:
		$a0 = { 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectv11MTEc
{
strings:
		$a0 = { 90 60 E8 1B ?? ?? ?? E9 FC }

condition:
		$a0 at entrypoint
}
	
	
rule CreateInstallStubvxx
{
strings:
		$a0 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 }
	$a1 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 BF 00 30 00 00 FF 15 20 61 40 00 50 FF 15 2C 61 40 00 6A 04 57 68 00 FF 01 00 56 FF 15 CC 60 40 00 6A 04 A3 CC 35 40 00 57 68 00 0F 01 00 56 FF 15 CC 60 40 00 68 00 01 00 00 BE B0 3F 40 00 56 A3 C4 30 40 00 FF 75 08 FF 15 10 61 40 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule BorlandDelphiv40v50
{
strings:
		$a0 = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
	$a1 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule UnknownJoinersignfrompinch260320070212
{
strings:
		$a0 = { 44 90 4C 90 B9 DE 00 00 00 BA 00 10 40 00 83 C2 03 44 90 4C B9 07 00 00 00 44 90 4C 33 C9 C7 05 08 30 40 00 00 00 00 00 90 68 00 01 00 00 68 21 30 40 00 6A 00 E8 C5 02 00 00 90 6A 00 68 80 }

condition:
		$a0 at entrypoint
}
	
	
rule WinZip32bitSFXv8xmodule
{
strings:
		$a0 = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 ?? ?? ?? ?? FF 15 }

condition:
		$a0 at entrypoint
}
	
	
rule Upxv12MarcusLazlo
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }

condition:
		$a0 at entrypoint
}
	
	
rule PEPACKv10byANAKiN1998
{
strings:
		$a0 = { 74 ?? E9 ?? ?? ?? ?? 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePCGuard4xxemadicius
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 }

condition:
		$a0
}
	
	
rule PEArmor049Hying
{
strings:
		$a0 = { 56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftC
{
strings:
		$a0 = { B4 30 CD 21 3C 02 73 ?? B8 }

condition:
		$a0 at entrypoint
}
	
	
rule VMProtect07x08PolyTech
{
strings:
		$a0 = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }

condition:
		$a0
}
	
	
rule MSLRH032afakeWWPack321xemadicius
{
strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 20 64 65 63 6F 6D 70 72 65 73 73 69 6F 6E 20 72 6F 75 74 69 6E 65 20 76 65 72 73 69 6F 6E 20 31 2E 31 32 0D 0A 28 63 29 20 31 39 39 38 20 50 69 6F 74 72 20 57 61 72 65 7A 61 6B 20 61 6E 64 20 52 }

condition:
		$a0
}
	
	
rule Armadillov300a
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB }

condition:
		$a0 at entrypoint
}
	
	
rule WerusCrypter10Kas
{
strings:
		$a0 = { 68 98 11 40 00 6A 00 E8 50 00 00 00 C9 C3 ED B3 FE FF FF 6A 00 E8 0C 00 00 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 }
	$a1 = { 68 98 11 40 00 6A 00 E8 50 00 00 00 C9 C3 ED B3 FE FF FF 6A 00 E8 0C 00 00 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 A8 10 40 00 FF 25 B0 10 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

condition:
		$a0 or $a1
}
	
	
rule PECompact20betastudentversionJeremyCollake
{
strings:
		$a0 = { B8 ?? ?? ?? EE 05 12 13 13 12 50 64 FF 35 00 00 00 00 64 89 25 00 }

condition:
		$a0
}
	
	
rule UnoPiX075BaGiE
{
strings:
		$a0 = { 60 E8 07 00 00 00 61 68 ?? ?? 40 00 C3 83 04 24 18 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 61 }

condition:
		$a0 at entrypoint
}
	
	
rule Themida10xx1800compressedengineOreansTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
	$a1 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 5A ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PEtitev22wwwun4seencompetite
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }

condition:
		$a0 at entrypoint
}
	
	
rule MSRunTimeLibrary199214
{
strings:
		$a0 = { 1E 06 8C C8 8E D8 8C C0 A3 ?? ?? 83 C0 ?? A3 ?? ?? B4 30 }

condition:
		$a0 at entrypoint
}
	
	
rule MSRunTimeLibrary199213
{
strings:
		$a0 = { BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB 33 DB B8 ?? ?? CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor224StrongbitSoftCompleteDevelopment
{
strings:
		$a0 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

condition:
		$a0
}
	
	
rule MSRunTimeLibrary199211
{
strings:
		$a0 = { B4 51 CD 21 8E DB B8 ?? ?? 83 E8 ?? 8E C0 33 F6 33 FF B9 ?? ?? FC F3 A5 }

condition:
		$a0 at entrypoint
}
	
	
rule CHECKPRGc1992
{
strings:
		$a0 = { 33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv070
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }
	$a1 = { 60 E8 ?? ?? ?? ?? 58 83 ?? ?? 50 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 83 ?? ?? 31 DB EB }
	$a2 = { 8C CB B9 ?? ?? BE ?? ?? 89 F7 1E A9 ?? ?? 8D ?? ?? ?? 8E D8 05 ?? ?? 8E C0 FD F3 A5 FC 2E ?? ?? ?? ?? 73 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule UPXv072
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 83 ?? ?? 31 DB 5E 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule HideProtectV10XSoftWarCompany
{
strings:
		$a0 = { 90 90 90 E9 D8 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor11CGSoftLabs
{
strings:
		$a0 = { E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxEddie1028
{
strings:
		$a0 = { E8 ?? ?? 5E FC 83 ?? ?? 81 ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E B8 FE 4B CD 21 81 FF BB 55 ?? ?? 07 ?? ?? ?? 07 B4 49 CD 21 BB FF FF B4 48 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule PEQuakev006byfORGAT
{
strings:
		$a0 = { E8 A5 00 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 3D ?? 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? 00 00 5B ?? 00 00 6E ?? 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 5D 81 ED 05 00 00 00 8D 75 3D 56 FF 55 31 8D B5 81 00 00 00 56 50 FF 55 2D 89 85 8E 00 00 00 6A 04 68 00 10 00 00 68 ?? ?? 00 00 6A 00 FF 95 8E 00 00 00 50 8B 9D 7D 00 00 00 03 DD 50 53 E8 04 00 00 00 5A 55 FF E2 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB }

condition:
		$a0
}
	
	
rule bambamV004bedrockSignbyfly
{
strings:
		$a0 = { BF ?? ?? ?? ?? 83 C9 FF 33 C0 68 ?? ?? ?? ?? F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 11 0A 00 00 83 C4 0C 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F0 BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 BF ?? ?? ?? ?? 8B D1 68 ?? ?? ?? ?? C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 C0 09 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule DzAPatcher13Loader
{
strings:
		$a0 = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 }

condition:
		$a0
}
	
	
rule tElockv071b7
{
strings:
		$a0 = { 60 E8 48 11 00 00 C3 83 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv071b2
{
strings:
		$a0 = { 60 E8 44 11 00 00 C3 83 }

condition:
		$a0 at entrypoint
}
	
	
rule MIDIMusicfile
{
strings:
		$a0 = { 4D 54 68 64 00 00 00 06 ?? ?? ?? ?? ?? ?? 4D 54 }

condition:
		$a0
}
	
	
rule SDProtectorProEdition116RandyLih
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 93 03 00 00 03 C8 74 C4 75 C2 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule DIETv100v100d
{
strings:
		$a0 = { BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtectorV102AshkbizDanehkarSignbyfly
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3A 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 C3 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

condition:
		$a0 at entrypoint
}
	
	
rule APEX_CBLTApex40500mhz
{
strings:
		$a0 = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 }

condition:
		$a0 at entrypoint
}
	
	
rule PELockNTv203
{
strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule StealthPEv11
{
strings:
		$a0 = { BA ?? ?? ?? 00 FF E2 BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackFullEdition117DLLAp0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }

condition:
		$a0 at entrypoint
}
	
	
rule AppEncryptorSilentTeam
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }

condition:
		$a0 at entrypoint
}
	
	
rule VirogenCryptv075
{
strings:
		$a0 = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01 }

condition:
		$a0 at entrypoint
}
	
	
rule SymantecWinFaxPRO83CoverpageQuickCoverPage
{
strings:
		$a0 = { FF FF ?? ?? ?? ?? ?? 43 6F 76 65 72 44 61 74 61 62 61 73 65 }

condition:
		$a0
}
	
	
rule WWPACKv300v301Extractable
{
strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC }

condition:
		$a0 at entrypoint
}
	
	
rule FSG120EngdulekxtBorlandC
{
strings:
		$a0 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }

condition:
		$a0
}
	
	
rule VxUddy2617
{
strings:
		$a0 = { 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? 8C C8 8E D8 8C ?? ?? ?? 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? 8C C8 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? B8 AB 9C CD 2F 3D 76 98 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01MicrosoftVisualC60DebugVersion
{
strings:
		$a0 = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule PLINK8619841985
{
strings:
		$a0 = { FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26 }

condition:
		$a0 at entrypoint
}
	
	
rule MEW11SEv10Northfox
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C ?0 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv10804AlexeySolodovnikov
{
strings:
		$a0 = { 60 E8 41 06 00 00 EB 41 }

condition:
		$a0 at entrypoint
}
	
	
rule aPackv098m
{
strings:
		$a0 = { 1E 06 8C C8 8E D8 05 ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B2 ?? BD ?? ?? 33 C9 50 A4 BB ?? ?? 3B F3 76 }

condition:
		$a0
}
	
	
rule MSLRH032afakeUPX0896102105124emadicius
{
strings:
		$a0 = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 }

condition:
		$a0
}
	
	
rule PESHiELDv02v02bv02b2
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealthv27
{
strings:
		$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }

condition:
		$a0 at entrypoint
}
	
	
rule VxHaryanto
{
strings:
		$a0 = { 81 EB 2A 01 8B 0F 1E 5B 03 CB 0E 51 B9 10 01 51 CB }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPackerv100LZBRS
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 1C 00 00 00 72 03 A4 EB F2 E8 1A 00 00 00 8D 51 FF E8 12 00 00 00 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }
	$a1 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule BeRoEXEPackerv100LZBRR
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPack32v1x
{
strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 }

condition:
		$a0 at entrypoint
}
	
	
rule Go32Stubv200DOSExtender
{
strings:
		$a0 = { 0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 80 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPRStripperv2xunpacked
{
strings:
		$a0 = { BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 9C FC BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 AA 9D 61 C3 55 8B EC }

condition:
		$a0 at entrypoint
}
	
	
rule PEncryptv10
{
strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 28 03 00 00 BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 }

condition:
		$a0 at entrypoint
}
	
	
rule Shrinker33
{
strings:
		$a0 = { 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

condition:
		$a0
}
	
	
rule Shrinker32
{
strings:
		$a0 = { 55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04 }

condition:
		$a0
}
	
	
rule IDApplicationProtectorV12IDSecuritySuiteSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F2 0B 47 00 B9 19 22 47 00 81 E9 EA 0E 47 00 89 EA 81 C2 EA 0E 47 00 8D 3A 89 FE 31 C0 E9 D3 02 00 00 CC CC CC CC E9 CA 02 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 6F 66 74 57 61 72 65 50 72 6F 74 65 63 74 6F 72 5C }

condition:
		$a0 at entrypoint
}
	
	
rule FSG133Engdulekxt
{
strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02CodeSafe20
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtectorV101AshkbizDanehkarSignbyfly
{
strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED D5 E4 41 00 8B D5 81 C2 23 E5 41 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 }

condition:
		$a0 at entrypoint
}
	
	
rule PreparedbySLROPTLINK
{
strings:
		$a0 = { 87 C0 55 56 57 52 51 53 50 9C FC 8C DA 83 ?? ?? 16 07 0E 1F }

condition:
		$a0 at entrypoint
}
	
	
rule StarForceV3XDLLStarForceCopyProtectionSystem
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorv120b
{
strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? 00 2B 05 84 ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 16 A1 ?? ?? ?? 00 03 05 80 ?? ?? 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 ?? ?? ?? 00 8D 84 05 EF FE FF FF 89 85 38 FE FF FF 8B 85 38 FE FF FF 0F BE 00 83 F8 5C }

condition:
		$a0
}
	
	
rule PEZip10byBaGIE
{
strings:
		$a0 = { D9 D0 F8 74 02 23 DB F5 F5 50 51 52 53 8D 44 24 10 50 55 56 57 D9 D0 22 C9 C1 F7 A0 55 66 C1 C8 B0 5D 81 E6 FF FF FF FF F8 77 07 52 76 03 72 01 90 5A C1 E0 60 90 BD 1F 01 00 00 87 E8 E2 07 E3 05 17 5D 47 E4 42 41 7F 06 50 66 83 EE 00 58 25 FF FF FF FF 51 }

condition:
		$a0
}
	
	
rule EPWv12
{
strings:
		$a0 = { 06 57 1E 56 55 52 51 53 50 2E ?? ?? ?? ?? 8C C0 05 ?? ?? 2E ?? ?? ?? 8E D8 A1 ?? ?? 2E }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPackerv100DLLBeRoFarbrausch
{
strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }
	$a1 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 BA ?? ?? ?? ?? 8D B2 }
	$a2 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule ASProtectv12x
{
strings:
		$a0 = { 00 00 68 01 ?? ?? ?? C3 AA }

condition:
		$a0 at entrypoint
}
	
	
rule FreePascal104Win32DLLBercziGaborPierreMullerPeterVreman
{
strings:
		$a0 = { C6 05 ?? ?? ?? ?? 00 55 89 E5 53 56 57 8B 7D 08 89 3D ?? ?? ?? ?? 8B 7D 0C 89 3D ?? ?? ?? ?? 8B 7D 10 89 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5B 5D C2 0C 00 }

condition:
		$a0
}
	
	
rule Packanoidv1Arkanoid
{
strings:
		$a0 = { BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 9D 00 00 00 B8 ?? ?? ?? ?? 8B 30 8B 78 04 BB ?? ?? ?? ?? 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacKNetLiuXingPingSignbyfly
{
strings:
		$a0 = { 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 BB 01 47 65 74 53 79 73 74 65 6D 49 6E 66 6F 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 5E 00 5F 43 6F 72 ?? ?? ?? 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C }

condition:
		$a0
}
	
	
rule ThinstallEmbeddedV2501JititSignbyfly
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D A8 1A 00 00 B9 6D 1A 00 00 BA 21 1B 00 00 BE 00 10 00 00 BF C0 53 00 00 BD F0 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }

condition:
		$a0 at entrypoint
}
	
	
rule MSRunTimeLibrary199007
{
strings:
		$a0 = { 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F 8B 1E ?? ?? 0B DB 74 ?? 8C D1 8B D4 FA 8E D3 BC ?? ?? FB }

condition:
		$a0 at entrypoint
}
	
	
rule VisualUPX02emadicius
{
strings:
		$a0 = { 66 C7 05 ?? ?? ?? 00 75 07 E9 ?? FE FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv02Beta
{
strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33 }

condition:
		$a0 at entrypoint
}
	
	
rule EscargotV01Meat
{
strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 }

condition:
		$a0 at entrypoint
}
	
	
rule Upack0399Dwing
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule MinGWGCC2x
{
strings:
		$a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SCObfuscatorSuperCRacker
{
strings:
		$a0 = { 60 33 C9 8B 1D 00 ?? ?? ?? 03 1D 08 ?? ?? ?? 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D 04 ?? ?? ?? 75 E7 A1 08 ?? ?? ?? 01 05 0C ?? ?? ?? 61 FF 25 0C }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectSKE2122dllAlexeySolodovnikovh
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule EXEStealth275WebtoolMaster
{
strings:
		$a0 = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UpackV037V039Dwing
{
strings:
		$a0 = { BE ?? ?? ?? ?? AD 50 FF ?? ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule PasswordProtectorcMiniSoft1992
{
strings:
		$a0 = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }

condition:
		$a0 at entrypoint
}
	
	
rule VxEddie2000
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C5 ?? ?? ?? B4 30 CD 21 }

condition:
		$a0 at entrypoint
}
	
	
rule ErdasLANGISImagegraphicsformat
{
strings:
		$a0 = { 48 45 41 44 37 34 00 00 03 00 }

condition:
		$a0
}
	
	
rule ThinstallVirtualizationSuiteV30XThinstallCompany
{
strings:
		$a0 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW32xDll_main
{
strings:
		$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 }

condition:
		$a0
}
	
	
rule eXPressorv14CGSoftLabs
{
strings:
		$a0 = { 65 58 50 72 2D 76 2E 31 2E 34 2E }

condition:
		$a0
}
	
	
rule SkDUndetectablerPro20NoUPXMethodSkD
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40 }

condition:
		$a0 at entrypoint
}
	
	
rule RJcrushv100
{
strings:
		$a0 = { 06 FC 8C C8 BA ?? ?? 03 D0 52 BA ?? ?? 52 BA ?? ?? 03 C2 8B D8 05 ?? ?? 8E DB 8E C0 33 F6 33 FF B9 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeShieldv27
{
strings:
		$a0 = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeShieldv29
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtMicrosoftVisualC5060
{
strings:
		$a0 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }

condition:
		$a0 at entrypoint
}
	
	
rule PellesC290EXEX86CRTLIB
{
strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 ?? ?? ?? ?? 59 A3 }

condition:
		$a0
}
	
	
rule MinGW32xmain
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D }

condition:
		$a0
}
	
	
rule ASProtect23SKEbuild0426Beta
{
strings:
		$a0 = { 68 01 60 40 00 E8 01 00 00 00 C3 C3 0D 6C 65 3E 09 84 BB 91 89 38 D0 5A 1D 60 6D AF D5 51 2D A9 2F E1 62 D8 C1 5A 8D 6B 6E 94 A7 F9 1D 26 8C 8E FB 08 A8 7E 9D 3B 0C DF 14 5E 62 14 7D 78 D0 6E }

condition:
		$a0
}
	
	
rule ASPackv212
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
	$a1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule ASPackv211
{
strings:
		$a0 = { 60 E9 3D 04 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SLROPTLINK1
{
strings:
		$a0 = { 87 C0 EB ?? 71 ?? 02 D8 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack10betaap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 }
	$a1 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MinGWv32xDll_main
{
strings:
		$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 F4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 3B 02 00 00 E8 C6 01 00 00 E9 75 FF FF FF E8 BC 05 00 00 C7 00 0C 00 00 00 31 C0 EB 98 89 F6 55 89 E5 83 EC 08 89 5D FC 8B 15 00 30 00 10 85 D2 74 29 8B 1D 10 30 00 10 83 EB 04 39 D3 72 0D 8B 03 85 C0 75 2A 83 EB 04 39 D3 73 F3 89 14 24 E8 6B 05 00 00 31 C0 A3 00 30 00 10 C7 04 24 00 00 00 00 E8 48 05 00 00 8B 5D FC 89 EC 5D C3 }

condition:
		$a0 at entrypoint
}
	
	
rule nMacrorecorder10
{
strings:
		$a0 = { 5C 6E 6D 72 5F 74 65 6D 70 2E 6E 6D 72 00 00 00 72 62 00 00 58 C7 41 00 10 F8 41 00 11 01 00 00 00 00 00 00 46 E1 00 00 46 E1 00 00 35 00 00 00 F6 88 41 00 }

condition:
		$a0
}
	
	
rule MSLRHv032afakeEXE32Pack13xemadiciush
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 90 83 C4 14 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule PrivateEXEv20a
{
strings:
		$a0 = { 53 E8 00 00 00 00 5B 8B C3 2D }
	$a1 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }
	$a2 = { 06 60 C8 ?? ?? ?? 0E 68 ?? ?? 9A ?? ?? ?? ?? 3D ?? ?? 0F ?? ?? ?? 50 50 0E 68 ?? ?? 9A ?? ?? ?? ?? 0E }
	$a3 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D ?? ?? ?? ?? 50 81 ?? ?? ?? ?? ?? 8B }

condition:
		$a0 at entrypoint or $a1 or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule PackmanV10BrandonLaCombe
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032aemadiciush
{
strings:
		$a0 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 }
	$a1 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF FF FF 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C }

condition:
		$a0 or $a1
}
	
	
rule PseudoSigner01PEX099Anorganix
{
strings:
		$a0 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PAKSFXArchive
{
strings:
		$a0 = { 55 8B EC 83 ?? ?? A1 ?? ?? 2E ?? ?? ?? 2E ?? ?? ?? ?? ?? 8C D7 8E C7 8D ?? ?? BE ?? ?? FC AC 3C 0D }

condition:
		$a0 at entrypoint
}
	
	
rule StonyBrookPascalv70
{
strings:
		$a0 = { 31 ED 9A ?? ?? ?? ?? 55 89 E5 81 EC ?? ?? B8 ?? ?? 0E 50 9A ?? ?? ?? ?? BE ?? ?? 1E 0E BF ?? ?? 1E 07 1F FC }

condition:
		$a0 at entrypoint
}
	
	
rule SimbiOZ13Extranger
{
strings:
		$a0 = { 57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv098tHEEGOiSTEh
{
strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule FSG13
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }

condition:
		$a0
}
	
	
rule NsPack31NorthStarh
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }

condition:
		$a0
}
	
	
rule Armadillov2xxCopyMemII
{
strings:
		$a0 = { 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82 }

condition:
		$a0 at entrypoint
}
	
	
rule iPBProtectv013
{
strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED 71 EB EB FA FF 83 C0 FC EB FF 70 ED 71 EB EB FA 0F 83 C0 F8 EB FF 70 ED 71 EB EB FA FF 83 C0 18 EB FF 70 }

condition:
		$a0
}
	
	
rule EXE2COMMethod1
{
strings:
		$a0 = { 8C DB BE ?? ?? 8B C6 B1 ?? D3 E8 03 C3 03 ?? ?? A3 ?? ?? 8C C8 05 ?? ?? A3 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv20
{
strings:
		$a0 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 }

condition:
		$a0
}
	
	
rule EncryptPEV22006115WFS
{
strings:
		$a0 = { 45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 36 2E 31 2E 31 35 }

condition:
		$a0
}
	
	
rule tElockv099SpecialBuildheXerforgot
{
strings:
		$a0 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule XXPack01bagie
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 00 68 00 ?? ?? ?? C3 }

condition:
		$a0 at entrypoint
}
	
	
rule PrivateEXEProtector197SetiSofth
{
strings:
		$a0 = { 55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB BA 00 00 00 80 C7 44 24 14 08 00 00 00 43 8D A4 24 00 00 00 00 8B FF 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 2C 8B 4C 24 10 33 C0 8D A4 24 00 00 00 00 05 }
	$a1 = { 55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB BA 00 00 00 80 C7 44 24 14 08 00 00 00 43 8D A4 24 00 00 00 00 8B FF 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 2C 8B 4C 24 10 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 02 44 24 0C 88 07 47 EB C6 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 82 6E 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 83 DC 00 00 00 B9 04 00 00 00 33 C0 8D A4 24 00 00 00 00 8D 64 24 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 48 74 B1 0F 89 EF 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 42 BD 00 01 00 00 B9 08 00 00 00 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 88 07 47 4D 75 D6 }

condition:
		$a0 or $a1
}
	
	
rule UpackV03XDwing
{
strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E }

condition:
		$a0 at entrypoint
}
	
	
rule FSG110EngdulekxtMASM32TASM32
{
strings:
		$a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }

condition:
		$a0 at entrypoint
}
	
	
rule UPXV194MarkusOberhumerampLaszloMolnarampJohnReiser
{
strings:
		$a0 = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

condition:
		$a0
}
	
	
rule EncryptedbyRSCC286v101
{
strings:
		$a0 = { FE 52 53 43 43 2F 31 2E 30 31 FE }

condition:
		$a0
}
	
	
rule Morphine27Holy_FatherRatter29Ah
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

condition:
		$a0
}
	
	
rule ORiEN211DEMO
{
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }

condition:
		$a0
}
	
	
rule EncryptedbyRSCC286v102
{
strings:
		$a0 = { FE 52 53 43 43 2F 31 2E 30 32 FE }

condition:
		$a0
}
	
	
rule Litev003a
{
strings:
		$a0 = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePack1XMethod2bagie
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule PKLITE3211PKWAREInc
{
strings:
		$a0 = { 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 00 00 00 00 E8 ?? ?? ?? ?? E9 }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector10Xvcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 E8 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 05 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ExactAudioCopyUnknownCompiler
{
strings:
		$a0 = { E8 ?? ?? ?? 00 31 ED 55 89 E5 81 EC ?? 00 00 00 8D BD ?? FF FF FF B9 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv010v012BetaSignbyhot_UNP
{
strings:
		$a0 = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01UPX06Anorganix
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule BJFntv12RC
{
strings:
		$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }

condition:
		$a0 at entrypoint
}
	
	
rule FishPEShield112116HellFish
{
strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC }
	$a1 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 BD FE FF FF 89 45 DC E8 E1 FD FF FF 8B 00 03 45 DC 89 45 E4 E8 DC FE FF FF 8B D8 BA 8E 4E 0E EC 8B C3 E8 2E FF FF FF 89 45 F4 BA 04 49 32 D3 8B C3 E8 1F FF FF FF 89 45 F8 BA 54 CA AF 91 8B C3 E8 10 FF FF FF 89 45 F0 BA AC 33 06 03 8B C3 E8 01 FF FF FF 89 45 EC BA 1B C6 46 79 8B C3 E8 F2 FE FF FF 89 45 E8 BA AA FC 0D 7C 8B C3 E8 E3 FE FF FF 89 45 FC 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B }
	$a2 = { 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00 }
	$a3 = { 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00 ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 ?? ?? 00 ?? ?? 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 00 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 40 }

condition:
		$a0 or $a1 or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule EncapsulatedPostscriptgraphicsfilev30EPSF30
{
strings:
		$a0 = { 25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 2E 30 }

condition:
		$a0
}
	
	
rule BeRoEXEPackerv100BeRoFarbrausch
{
strings:
		$a0 = { 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 BA ?? ?? ?? ?? 8D B2 }
	$a1 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC ?? ?? ?? ?? A4 ?? ?? ?? ?? 00 ?? ?? ?? ?? 33 C9 E8 64 00 00 00 73 1C ?? ?? ?? ?? 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 ?? ?? ?? ?? D4 E8 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule MSLRHv032afakeWWPack321xemadiciush
{
strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 20 64 65 63 6F 6D 70 72 65 73 73 69 6F 6E 20 72 6F 75 74 69 6E 65 20 76 65 72 73 69 6F 6E 20 31 2E 31 32 0D 0A 28 63 29 20 31 39 39 38 20 50 69 6F 74 72 20 57 61 72 65 7A 61 6B 20 61 6E 64 20 52 61 66 61 6C 20 57 69 65 72 7A 62 69 63 6B 69 0D 0A 0D 0A 5D 5B 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule CodeCryptv016bv0163b
{
strings:
		$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinv13betaCyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 ?? 4E 40 00 8B 42 3C 03 C2 89 85 ?? 4E 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D ?? 4E 40 00 53 8F 85 ?? 4C 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD ?? 4F 40 00 8D 5B 04 8B 1B 89 9D ?? 4F 40 00 E8 00 00 00 00 58 01 68 05 68 BC 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC FF 25 10 BB ?? 00 00 00 B9 84 12 00 00 8D BD ?? 4F 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }

condition:
		$a0 at entrypoint
}
	
	
rule VOBProtectCD
{
strings:
		$a0 = { 5F 81 EF ?? ?? ?? ?? BE ?? ?? 40 ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7 ?? ?? ?? ?? FF 10 89 87 ?? ?? ?? ?? 5E 5F }

condition:
		$a0 at entrypoint
}
	
	
rule Excalibur103forgot
{
strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PCGuardforWin32v500SofProBlagojeCeklich
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 ?? ?? ?? 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 }

condition:
		$a0 at entrypoint
}
	
	
	
rule SymantecVisualCafev30
{
strings:
		$a0 = { 64 8B 05 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? 40 ?? 68 ?? ?? 40 ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 08 50 53 56 57 89 65 E8 C7 45 FC }

condition:
		$a0 at entrypoint
}
	
	
rule Shrinker34
{
strings:
		$a0 = { 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04 }

condition:
		$a0
}
	
	
rule SentinelSuperProAutomaticProtection640Safenet
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 }

condition:
		$a0
}
	
	
rule PEBundlev310
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01 }

condition:
		$a0
}
	
	
rule NsPack34NorthStar
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 }
	$a1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PellesC280290EXEX86CRTLIB
{
strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 ?? E8 ?? ?? ?? ?? 59 A3 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphi3PortionsCopyrightc198396Borlandh
{
strings:
		$a0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 36 20 42 6F 72 6C 61 6E 64 00 }

condition:
		$a0
}
	
	
rule eXpressorv10CGSoftLabs
{
strings:
		$a0 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 }

condition:
		$a0
}
	
	
rule PellesC28x45xPelleOrinius
{
strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystem20a0
{
strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 }

condition:
		$a0
}
	
	
rule Thinstallv2460Jitit
{
strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 F4 18 40 00 50 E8 87 FC FF FF 59 59 A1 94 1A 40 00 8B 40 10 03 05 90 1A 40 00 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 76 0C 00 00 D4 0C 00 00 1E }

condition:
		$a0 at entrypoint
}
	
	
rule SafeDiscSafeCast2xx3xxMacrovision
{
strings:
		$a0 = { 55 8B EC 60 BB ?? ?? ?? ?? 33 C9 8A 0D 3D ?? ?? ?? 85 C9 74 0C B8 ?? ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 ?? ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 09 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 76 00 00 00 83 C4 08 59 83 F8 00 74 1C }
	$a1 = { 55 8B EC 60 BB ?? ?? ?? ?? 33 C9 8A 0D 3D ?? ?? ?? 85 C9 74 0C B8 ?? ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 ?? ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 09 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 76 00 00 00 83 C4 08 59 83 F8 00 74 1C C6 03 C2 C6 43 01 0C 85 C9 74 09 61 5D B8 00 00 00 00 EB 97 50 A1 29 ?? ?? ?? ?? D0 61 5D EB 46 80 7C 24 08 00 75 3F 51 8B 4C 24 04 89 0D ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 4C 24 04 59 EB 28 50 B8 2D ?? ?? ?? ?? 70 08 8B 40 0C FF D0 B8 2D ?? ?? ?? ?? 30 8B 40 04 FF D0 58 FF 35 ?? ?? ?? ?? C3 72 16 61 13 60 0D E9 ?? ?? ?? ?? CC CC 81 EC E8 02 00 00 53 55 56 57 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule FSGv110Engdulekxt
{
strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
	$a1 = { E8 01 00 00 00 ?? ?? E8 ?? 00 00 00 }
	$a2 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule AudioCDfile
{
strings:
		$a0 = { 52 49 46 46 ?? ?? ?? ?? 43 44 44 41 66 6D 74 }

condition:
		$a0
}
	
	
rule PECompactv2xx
{
strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

condition:
		$a0
}
	
	
rule MicrosoftCLibrary1985
{
strings:
		$a0 = { BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 81 C4 ?? ?? FB 73 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo440SiliconRealmsToolworks
{
strings:
		$a0 = { 31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov1xxv2xx
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOPv111c
{
strings:
		$a0 = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB ?? ?? 5B EB }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealth276UnregisteredWebtoolMaster
{
strings:
		$a0 = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }

condition:
		$a0
}
	
	
rule FileAnalyzerRegistrationfilev11
{
strings:
		$a0 = { 24 46 41 52 45 47 24 45 4E 43 3D ?? 26 26 52 45 47 3D ?? 26 26 45 58 50 3D }

condition:
		$a0
}
	
	
rule FileAnalyzerRegistrationfilev10
{
strings:
		$a0 = { 24 46 41 52 45 47 24 4D 2D ?? ?? ?? ?? 31 }

condition:
		$a0
}
	
	
rule CDSSSv10Beta1CyberDoomTeamX
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv032afakeUPX0896102105124emadiciush
{
strings:
		$a0 = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv041x
{
strings:
		$a0 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }

condition:
		$a0 at entrypoint
}
	
	
rule ZCodeWin32PEProtectorv101
{
strings:
		$a0 = { E9 12 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 FB FF FF FF C3 68 ?? ?? ?? ?? 64 FF 35 }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1250ObsidiumSoftware
{
strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 }
	$a1 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ABCCryptor10byZloY
{
strings:
		$a0 = { 68 FF 64 24 F0 68 58 58 58 58 90 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 ?? ?? ?? ?? BF 00 ?? ?? ?? B9 00 ?? ?? ?? 80 37 ?? 47 39 CF 75 F8 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualCv60DLL
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C }
	$a1 = { 55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84 }
	$a2 = { 83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? ?? 00 10 E8 8B FF FF FF }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule TurboProfilerAreasfile
{
strings:
		$a0 = { 54 75 72 62 6F ?? 50 72 6F 66 69 6C 65 72 ?? 61 72 65 61 73 ?? 66 69 6C 65 }

condition:
		$a0
}
	
	
rule FSGv120EngdulekxtMicrosoftVisualC60
{
strings:
		$a0 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 EB 02 42 C0 EB 01 08 88 16 80 F1 98 80 C9 28 46 91 EB 02 C0 55 4B EB 01 55 34 44 0B DB 75 AD E8 01 00 00 00 9D 59 0B C6 EB 01 6C E9 D2 C3 82 C2 03 C2 B2 82 C2 00 ?? ?? 7C C2 6F DA BC C2 C2 C2 CC 1C 3D CF 4C D8 84 D0 0C FD F0 42 77 0D 66 F1 AC C1 DE CE 97 BA D7 EB C3 AE DE 91 AA D5 02 0D 1E EE 3F 23 77 C4 01 72 12 C1 0E 1E 14 82 37 AB 39 01 88 C9 DE CA 07 C2 C2 C2 17 79 49 B2 DA 0A C2 C2 C2 A9 EA 6E 91 AA 2E 03 CF 7B 9F CE 51 FA 6D A2 AA 56 8A E4 C2 C2 C2 07 C2 47 C2 C2 17 B8 42 C6 8D 31 88 45 BA 3D 2B BC }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallVirtualizationSuiteV310XThinstallCompany
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 2C FF FF FF E9 90 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv100b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }

condition:
		$a0 at entrypoint
}
	
	
rule Crypter31SLESH
{
strings:
		$a0 = { 68 FF 64 24 F0 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 }

condition:
		$a0 at entrypoint
}
	
	
rule InnoInstallerv512
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB DC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 50 00 00 68 D8 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC }

condition:
		$a0
}
	
	
rule PseudoSigner01VBOX43MTEAnorganix
{
strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule FreeCryptor02build002GlOFF
{
strings:
		$a0 = { 33 D2 90 1E 68 1B ?? ?? ?? 0F A0 1F 8B 02 90 50 54 8F 02 90 90 8E 64 24 08 FF E2 58 50 33 D2 52 83 F8 01 9B 40 8A 10 89 14 24 90 D9 04 24 90 D9 FA D9 5C 24 FC 8B 5C 24 FC 81 F3 C2 FC 1D 1C 75 E3 74 01 62 FF D0 90 5A 33 C0 8B 54 24 08 90 64 8F 00 90 83 C2 08 52 5C 5A }

condition:
		$a0
}
	
	
rule UPXv062
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }
	$a1 = { 60 E8 ?? ?? ?? ?? 58 83 ?? ?? 50 8D ?? ?? ?? ?? ?? 57 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? 31 DB ?? ?? ?? EB }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PEArmorV07XHying
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 81 C5 ?? ?? ?? ?? 55 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule PackItBitchV10archphase
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXShit01500mhz
{
strings:
		$a0 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
	$a1 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule LamCrypt10LaZaRuS
{
strings:
		$a0 = { 60 66 9C BB 00 ?? ?? 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 }

condition:
		$a0
}
	
	
rule nPackv11250BetaNEOx
{
strings:
		$a0 = { 83 3D 04 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E ?? ?? ?? 2B 05 08 ?? ?? ?? A3 00 ?? ?? ?? E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 ?? ?? ?? C7 05 04 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 56 57 68 }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSafeguardv10simonzhh
{
strings:
		$a0 = { C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE FF FF FF DF BA A3 22 3F 9A C0 60 EB 4D EB 47 DF 69 4E 58 DF 59 79 F3 EB 01 DF 78 EE DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE FF FF FF E8 BA A3 22 3F 9A C0 8D B5 EE 19 40 00 EB 47 EB 47 DF 69 4E 58 DF 59 7A EE EB 01 DF 7B E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE FF FF FF DF 22 3F 9A C0 8B FE EB 4C EB 47 DF 69 4E 58 DF 59 74 F2 EB 01 DF 75 ED 0F 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE FF FF FF E8 BA A3 22 3F 9A C0 B9 2B CB 00 00 EB 4B EB 47 DF 69 4E 58 DF 59 78 EF }

condition:
		$a0
}
	
	
rule PseudoSigner01VideoLanClientAnorganix
{
strings:
		$a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01DxPack10Anorganix
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Splice11byTw1stedL0gic
{
strings:
		$a0 = { 68 00 1A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 ?? ?? ?? ?? ?? ?? 50 72 6F 6A 65 63 74 31 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 06 00 00 00 AC }
	$a1 = { 68 00 1A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 ?? ?? ?? ?? ?? ?? 50 72 6F 6A 65 63 74 31 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 06 00 00 00 AC 29 40 00 07 00 00 00 BC 28 40 00 07 00 00 00 74 28 40 00 07 00 00 00 2C 28 40 00 07 00 00 00 08 23 40 00 01 00 00 00 38 21 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 8C 21 40 00 08 ?? 40 00 01 00 00 00 AC 19 40 00 00 00 00 00 00 00 00 00 00 00 00 00 AC 19 40 00 4F 00 43 00 50 00 00 00 E7 AF 58 2F 9A 4C 17 4D B7 A9 CA 3E 57 6F F7 76 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule WinUpackv039finalByDwingc2005
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 AC FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F3 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 46 AD 85 C0 74 1F 51 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv140v145
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo300aSiliconRealmsToolworks
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F }
	$a1 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 ?? 87 DB 7A F0 ?? ?? 61 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 ?? 8B 04 24 EB 03 7A 29 ?? C6 00 90 C3 ?? 70 F0 87 D2 71 07 ?? ?? 40 8B DB 7A 11 EB 08 ?? EB F7 EB C3 ?? 7A E9 70 DA 7B D1 71 F3 ?? 7B F3 71 D6 ?? 9D 61 83 ED 06 33 FF 47 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 EB 87 ?? 7A F0 ?? ?? 61 8B 9C BD 26 42 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule NullsoftInstallSystemv20b4
{
strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 68 E4 91 40 00 56 FF D3 E8 7C FF FF FF 85 C0 0F 84 59 01 00 00 BE E0 66 42 00 56 FF 15 68 70 40 00 68 D8 91 40 00 56 E8 FE 27 00 00 57 FF 15 BC 70 40 00 BE 00 C0 42 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 C0 42 00 22 A3 E0 6E 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 C0 42 00 8B 3D 10 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52 }
	$a1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 40 00 03 C6 50 E8 78 29 00 00 56 E8 47 2B 00 00 6A 00 56 FF D3 56 57 E8 EA 25 00 00 85 C0 75 0D C7 44 24 14 58 91 40 00 E9 72 02 00 00 57 FF 15 24 71 40 00 68 EC 91 40 00 57 E8 43 }

condition:
		$a0 or $a1
}
	
	
rule BorlandC19921994
{
strings:
		$a0 = { 8C C8 8E D8 8C 1E ?? ?? 8C 06 ?? ?? 8C 06 ?? ?? 8C 06 }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPackerV100BeRo
{
strings:
		$a0 = { BA ?? ?? ?? ?? 8D B2 ?? ?? ?? ?? 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15 ?? ?? ?? ?? 5F 5A 85 C0 74 2F 8B C8 8B 03 85 C0 74 22 0F BA F0 1F 72 04 8D 44 ?? ?? 51 52 57 50 51 FF 15 ?? ?? ?? ?? 5F 5A 59 85 C0 74 }

condition:
		$a0
}
	
	
rule TurboorBorlandPascalv70
{
strings:
		$a0 = { 9A ?? ?? ?? ?? C8 ?? ?? ?? 9A ?? ?? ?? ?? 09 C0 75 ?? EB ?? 8D ?? ?? ?? 16 57 6A ?? 9A ?? ?? ?? ?? BF ?? ?? 1E 57 68 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv305c4UnextrPasswcheckVirshield
{
strings:
		$a0 = { 03 05 C0 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRHv32aemadicius
{
strings:
		$a0 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 }
	$a1 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00  }
	$a2 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 }

condition:
		$a0 at entrypoint or $a1 or $a2
}
	
	
rule SpecialEXEPaswordProtectorv101EngPavolCerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E }
	$a1 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 00 00 8D 95 C6 77 00 00 8D 8D FF 77 00 00 55 68 00 20 00 00 51 52 6A 00 FF 95 04 7A 00 00 5D 6A 00 FF 95 FC 79 00 00 8D 8D 60 78 00 00 8D 95 85 01 00 00 55 68 00 04 00 00 52 6A 00 51 50 FF 95 08 7A 00 00 5D 8D B5 3F 78 00 00 6A 00 6A 00 6A 00 56 FF 95 0C 7A 00 00 0B C0 0F 84 FE 00 00 00 56 FF 95 10 7A 00 00 56 FF 95 14 7A 00 00 80 BD 3E 78 00 00 00 74 D4 33 D2 8B BD 3E 77 00 00 8D 85 1D 02 00 00 89 85 42 77 00 00 8D 85 49 02 00 00 89 85 46 77 00 00 8D 85 EB 75 00 00 89 85 4A 77 00 00 8B 84 D5 24 76 00 00 03 F8 8B 8C D5 28 76 00 00 3B 85 36 77 00 00 60 74 1F 8D B5 BD 02 00 00 FF D6 85 D2 75 11 60 87 FE 8D BD 15 78 00 00 B9 08 00 00 00 F3 A5 61 EB 15 8D 85 9F 02 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ASPackv1061b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystem206
{
strings:
		$a0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 02 23 00 00 BE ?? ?? ?? ?? 56 }

condition:
		$a0
}
	
	
rule PECompactv166
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv167
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 8B 11 }

condition:
		$a0 at entrypoint
}
	
	
rule CauseWayDOSExtenderv325
{
strings:
		$a0 = { FA 16 1F 26 ?? ?? ?? 83 ?? ?? 8E D0 FB 06 16 07 BE ?? ?? 8B FE B9 ?? ?? F3 A4 07 }

condition:
		$a0 at entrypoint
}
	
	
rule CrunchPE40
{
strings:
		$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 E9 06 ?? ?? 89 85 E1 06 ?? ?? FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }

condition:
		$a0
}
	
	
rule GPInstallv50332
{
strings:
		$a0 = { 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0 }

condition:
		$a0
}
	
	
rule VOBProtectCD5
{
strings:
		$a0 = { 36 3E 26 8A C0 60 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule WatcomCC
{
strings:
		$a0 = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 }
	$a1 = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 31 39 38 38 2D 31 39 39 35 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E 00 00 00 00 00 00 }

condition:
		$a0 or $a1
}
	
	
rule PatchCreationWizardv12BytePatch
{
strings:
		$a0 = { E8 7F 03 00 00 6A 00 E8 24 03 00 00 A3 B8 33 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 2C 03 00 00 6A 00 E8 EF 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 B8 33 40 00 E8 1B 03 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 1D 03 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 14 03 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 05 03 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 F6 02 00 00 6A 00 FF 75 08 E8 C8 02 00 00 A3 B4 33 40 00 C7 05 BC 33 40 00 2C 00 00 00 C7 05 C0 33 40 00 10 00 00 00 C7 05 C4 33 40 00 00 08 00 00 68 BC 33 40 00 6A 01 6A FF FF 35 B4 33 40 00 E8 97 02 00 00 C7 05 C4 33 40 00 00 00 00 00 C7 05 E0 33 40 00 00 30 40 00 C7 05 E4 33 40 00 01 00 00 00 68 BC 33 40 00 6A 01 6A FF FF 35 B4 33 40 00 E8 65 02 00 00 EB 5F EB 54 }

condition:
		$a0
}
	
	
rule MoleBoxV2XMoleStudiocom
{
strings:
		$a0 = { E8 00 00 00 00 60 E8 4F 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov410SiliconRealmsToolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 D0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 7C A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 78 A5 4C 00 C1 E1 08 03 CA 89 0D 74 A5 4C 00 C1 E8 10 A3 70 A5 4C 00 33 F6 56 E8 78 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 43 13 00 00 FF 15 8C 30 4C 00 A3 84 BB 4C 00 E8 01 12 00 00 A3 D0 A5 4C 00 E8 AA 0F 00 00 E8 EC 0E 00 00 E8 2D FA FF FF 89 }

condition:
		$a0
}
	
	
rule AverCryptor102betaos1r1s
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakeMicrosoftVisualCemadicius
{
strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 }

condition:
		$a0
}
	
	
rule SDProtectorBasicProEdition110RandyLih
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 64 A3 00 00 00 00 83 C4 08 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 59 03 00 00 03 C8 74 B8 75 B6 E8 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv037v038BetaStripbaserelocationtableOptionSignbyhot_UNP
{
strings:
		$a0 = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }

condition:
		$a0
}
	
	
rule FSGv131
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv133
{
strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }

condition:
		$a0 at entrypoint
}
	
	
rule VcasmProtector10a10dvcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule HidePE101BGCorp
{
strings:
		$a0 = { BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealthv11
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstallvxx
{
strings:
		$a0 = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule VxHafen1641
{
strings:
		$a0 = { E8 ?? ?? 01 ?? ?? ?? CE CC 25 ?? ?? 25 ?? ?? 25 ?? ?? 40 51 D4 ?? ?? ?? CC 47 CA ?? ?? 46 8A CC 44 88 CC }

condition:
		$a0 at entrypoint
}
	
	
rule yC13byAshkbizDanehkar
{
strings:
		$a0 = { 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

condition:
		$a0
}
	
	
rule MicrosoftVisualC20
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualC60DLLDebug
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 ?? ?? 83 }

condition:
		$a0
}
	
	
rule PrivatePersonalPackerPPP103ConquestOfTroycom
{
strings:
		$a0 = { E8 19 00 00 00 90 90 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }

condition:
		$a0 at entrypoint
}
	
	
rule VIRUSIWormBagle
{
strings:
		$a0 = { 6A 00 E8 95 01 00 00 E8 9F E6 FF FF 83 3D 03 50 40 00 00 75 14 68 C8 AF 00 00 E8 01 E1 FF FF 05 88 13 00 00 A3 03 50 40 00 68 5C 57 40 00 68 F6 30 40 00 FF 35 03 50 40 00 E8 B0 EA FF FF E8 3A FC FF FF 83 3D 54 57 40 00 00 74 05 E8 F3 FA FF FF 68 E8 03 00 }
	$a1 = { 6A 00 E8 95 01 00 00 E8 9F E6 FF FF 83 3D 03 50 40 00 00 75 14 68 C8 AF 00 00 E8 01 E1 FF FF 05 88 13 00 00 A3 03 50 40 00 68 5C 57 40 00 68 F6 30 40 00 FF 35 03 50 40 00 E8 B0 EA FF FF E8 3A FC FF FF 83 3D 54 57 40 00 00 74 05 E8 F3 FA FF FF 68 E8 03 00 00 E8 B1 00 00 00 EB F4 CC FF 25 A4 40 40 00 FF 25 B8 40 40 00 FF 25 B4 40 40 00 FF 25 B0 40 40 00 FF 25 AC 40 40 00 FF 25 9C 40 40 00 FF 25 A0 40 40 00 FF 25 A8 40 40 00 FF 25 24 40 40 00 FF 25 28 40 40 00 FF 25 2C 40 40 00 FF 25 30 40 40 00 FF 25 34 40 40 00 FF 25 38 40 40 00 FF 25 3C 40 40 00 FF 25 40 40 40 00 FF 25 44 40 40 00 FF 25 48 40 40 00 FF 25 4C 40 40 00 FF 25 50 40 40 00 FF 25 54 40 40 00 FF 25 58 40 40 00 FF 25 5C 40 40 00 FF 25 60 40 40 00 FF 25 BC 40 40 00 FF 25 64 40 40 00 FF 25 68 40 40 }

condition:
		$a0 or $a1
}
	
	
rule RLPackv118BasicLZMAAp0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }

condition:
		$a0 at entrypoint
}
	
	
rule XtremeProtector106
{
strings:
		$a0 = { B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 }

condition:
		$a0
}
	
	
rule NsPack31LiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }

condition:
		$a0
}
	
	
rule SecurePE1X
{
strings:
		$a0 = { 8B 04 24 E8 00 00 00 00 5D 81 ED 4C 2F 40 00 89 85 61 2F 40 00 8D 9D 65 2F 40 00 53 C3 00 00 00 00 8D B5 BA 2F 40 00 8B FE BB 65 2F 40 00 B9 C6 01 00 00 AD 2B C3 C1 C0 03 33 C3 AB 43 81 FB 8E 2F 40 00 75 05 BB 65 2F 40 00 E2 E7 89 AD 1A 31 40 00 89 AD 55 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv029betaDwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 }

condition:
		$a0 at entrypoint
}
	
	
rule StarForceV3XStarForceCopyProtectionSystem
{
strings:
		$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtectorv1032byAshkbizDanehkar
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 }

condition:
		$a0
}
	
	
rule UPXScramblerRCv1x
{
strings:
		$a0 = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02Gleam100
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV1334ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXFreakV01HMX0101
{
strings:
		$a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UnnamedScrambler20p0ke
{
strings:
		$a0 = { 55 8B EC B9 0A 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 1C 2F 40 00 E8 C8 F1 FF FF 33 C0 55 68 FB 33 40 00 64 FF 30 64 89 20 BA 0C 34 40 00 B8 E4 54 40 00 E8 EF FE FF FF 8B D8 85 DB 75 07 6A 00 E8 5A F2 FF FF BA E8 54 40 00 8B C3 8B 0D E4 54 40 00 E8 74 }
	$a1 = { 55 8B EC B9 0A 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 1C 2F 40 00 E8 C8 F1 FF FF 33 C0 55 68 FB 33 40 00 64 FF 30 64 89 20 BA 0C 34 40 00 B8 E4 54 40 00 E8 EF FE FF FF 8B D8 85 DB 75 07 6A 00 E8 5A F2 FF FF BA E8 54 40 00 8B C3 8B 0D E4 54 40 00 E8 74 E2 FF FF C7 05 20 6B 40 00 09 00 00 00 BB 98 69 40 00 C7 45 EC E8 54 40 00 C7 45 E8 31 57 40 00 C7 45 E4 43 60 40 00 BE D3 6A 40 00 BF E0 6A 40 00 83 7B 04 00 75 0B 83 3B 00 0F 86 AA 03 00 00 EB 06 0F 8E A2 03 00 00 8B 03 8B D0 B8 0C 6B 40 00 E8 C1 EE FF FF B8 0C 6B 40 00 E8 6F EE FF FF 8B D0 8B 45 EC 8B 0B E8 0B E2 FF FF 6A 00 6A 1E 6A 00 6A 2C A1 0C 6B 40 00 E8 25 ED FF FF 8D 55 E0 E8 15 FE FF FF 8B 55 E0 B9 10 6B 40 00 A1 0C 6B 40 00 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule HACKSTOPv100
{
strings:
		$a0 = { FA BD ?? ?? FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F }

condition:
		$a0 at entrypoint
}
	
	
rule ExeShield36wwwexeshieldcom
{
strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F }

condition:
		$a0 at entrypoint
}
	
	
rule Pe123v200644
{
strings:
		$a0 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 E8 00 00 00 00 58 C1 E8 0C C1 E0 0C 66 81 38 4D 5A 74 0C 2D 00 10 00 00 66 81 38 4D 5A 75 F4 C3 E8 00 00 00 00 58 83 E8 05 C3 8B C0 55 8B EC 81 C4 B8 FE FF FF 6A 40 8D 45 B0 50 E8 C0 FF FF FF 50 E8 8E FF FF FF 68 F8 00 00 00 8D 85 B8 FE FF FF 50 E8 A9 FF FF FF 03 45 EC 50 E8 74 FF FF FF E8 9B FF FF FF 03 85 38 FF FF FF 83 C0 34 89 45 FC E8 8A FF FF FF 03 85 38 FF FF FF 83 C0 38 89 45 F4 8B 45 FC }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv211d
{
strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv211b
{
strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv211c
{
strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PE_AdminV10EncryptPEV12003518SoldFlyingCat
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule CipherWallSelfExtratorDecryptorConsole15
{
strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }

condition:
		$a0
}
	
	
rule Armadillov265b1
{
strings:
		$a0 = { 55 8B EC 6A FF 68 38 ?? ?? ?? 68 40 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 F4 }

condition:
		$a0 at entrypoint
}
	
	
rule BobPackv100BoBBobSoft
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 }

condition:
		$a0 at entrypoint
}
	
	
rule NTkrnlSecureSuiteNTkrnlTeamBlue
{
strings:
		$a0 = { 68 29 19 43 00 E8 01 00 00 00 C3 C3 A2 A9 61 4E A5 0E C7 A6 59 90 6E 4D 4C DB 36 46 FB 6E C4 45 A3 C2 2E 0E 41 59 1A 50 17 39 62 4D B8 61 24 8E CF D1 0E 9E 7A 66 C0 8D 6B 9C 52 7E 96 46 80 AF }

condition:
		$a0
}
	
	
rule DBPEv210
{
strings:
		$a0 = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE }

condition:
		$a0 at entrypoint
}
	
	
rule NsPackv31NorthStar
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv07xv084
{
strings:
		$a0 = { 60 E8 00 00 C3 83 }

condition:
		$a0 at entrypoint
}
	
	
rule PENinja
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorPacKV150XCGSoftLabsSignbyfly
{
strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 04 }

condition:
		$a0 at entrypoint
}
	
	
rule UpackV036Dwing
{
strings:
		$a0 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }
	$a1 = { BE ?? ?? ?? ?? FF 36 E9 C3 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule UPolyXv05
{
strings:
		$a0 = { 83 EC 04 89 ?? 24 59 ?? ?? 00 00 00 }
	$a1 = { BB 00 BD 46 00 83 EC 04 89 1C 24 ?? B9 ?? 00 00 00 80 33 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a2 = { BB 00 BD 46 00 83 EC 04 89 1C 24 ?? B9 ?? 00 00 00 80 33 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 or $a1 or $a2
}
	
	
rule MinGWv32xWinMain
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 0C 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 5D 08 00 00 83 EC 04 E8 55 03 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 24 0C 8D 55 F4 89 54 24 08 C7 44 24 04 04 20 40 00 E8 D2 07 00 00 A1 20 20 40 00 85 C0 74 76 A3 30 20 40 00 A1 08 41 40 00 85 C0 74 1F 89 04 24 E8 93 07 00 00 8B 1D 20 20 40 00 89 04 24 89 5C 24 04 E8 91 07 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule yzpackV112UsArSignbyfly
{
strings:
		$a0 = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 ?? ?? ?? ?? B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 E0 00 ?? ?? 0B 01 ?? ?? ?? ?? 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UPX050070
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystem20
{
strings:
		$a0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }
	$a1 = { 83 EC 0C 53 55 56 57 C7 44 24 10 ?? ?? ?? ?? 33 DB C6 44 24 14 20 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 56 57 A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E8 8D FF FF FF 8B 2D ?? ?? ?? ?? 85 C0 }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule VxXRCV1015
{
strings:
		$a0 = { E8 ?? ?? 5E 83 ?? ?? 53 51 1E 06 B4 99 CD 21 80 FC 21 ?? ?? ?? ?? ?? 33 C0 50 8C D8 48 8E C0 1F A1 ?? ?? 8B }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackv118BasicDLLaPLibAp0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 }

condition:
		$a0 at entrypoint
}
	
	
rule KBySV028shooooSignbyfly
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 }

condition:
		$a0 at entrypoint
}
	
	
rule PellesC290300400DLLX86CRTLIB
{
strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }

condition:
		$a0
}
	
	
rule UnnamedScrambler13Bp0ke
{
strings:
		$a0 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 98 56 00 10 E8 48 EB FF FF 33 C0 55 68 AC 5D 00 10 64 FF 30 64 89 20 6A 00 68 BC 5D 00 10 68 C4 5D 00 10 6A 00 E8 23 EC FF FF E8 C6 CE FF FF 6A 00 68 BC 5D 00 10 68 ?? ?? ?? ?? 6A 00 E8 0B EC FF FF }
	$a1 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 98 56 00 10 E8 48 EB FF FF 33 C0 55 68 AC 5D 00 10 64 FF 30 64 89 20 6A 00 68 BC 5D 00 10 68 C4 5D 00 10 6A 00 E8 23 EC FF FF E8 C6 CE FF FF 6A 00 68 BC 5D 00 10 68 ?? ?? ?? ?? 6A 00 E8 0B EC FF FF E8 F2 F4 FF FF B8 08 BC 00 10 33 C9 BA 04 01 00 00 E8 C1 D2 FF FF 6A 00 68 BC 5D 00 10 68 E4 5D 00 10 6A 00 E8 E2 EB FF FF 68 04 01 00 00 68 08 BC 00 10 6A 00 FF 15 68 77 00 10 6A 00 68 BC 5D 00 10 68 FC 5D 00 10 6A 00 E8 BD EB FF FF BA 10 5E 00 10 B8 70 77 00 10 E8 CA F3 FF FF 85 C0 0F 84 F7 05 00 00 BA 74 77 00 10 8B 0D 70 77 00 10 E8 FE CD FF FF 6A 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RLPack118DllaPlib043ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 5C 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }

condition:
		$a0 at entrypoint
}
	
	
rule SimbiOZPolyCryptorvxxExtranger
{
strings:
		$a0 = { 55 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule AVPACKv120
{
strings:
		$a0 = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 ?? ?? FC F3 A5 06 BB ?? ?? 53 CB }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov220
{
strings:
		$a0 = { 55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule TurboPascalConfigurationFile
{
strings:
		$a0 = { 54 75 72 62 6F 20 50 61 73 63 61 6C 20 43 6F 6E 66 69 67 75 72 61 74 69 6F 6E }

condition:
		$a0
}
	
	
rule NullsoftInstallSystemv1xx
{
strings:
		$a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 56 56 56 89 75 E4 E8 C1 C9 FF FF 8B 1D 68 70 40 00 83 C4 0C 89 45 E8 89 75 F0 6A 02 56 6A FC 57 FF D3 89 45 FC 8D 45 F8 56 50 8D 45 E4 6A 04 50 57 FF 15 48 70 40 00 85 C0 75 07 BB 7C 9E 40 00 EB 7A 56 56 56 57 FF D3 39 75 FC 7E 62 BF 74 A2 40 00 B8 00 10 00 00 39 45 FC 7F 03 8B 45 FC 8D 4D F8 56 51 50 57 FF 75 EC FF 15 48 70 40 00 85 C0 74 5A FF 75 F8 57 FF 75 E8 E8 4D C9 FF FF 89 45 E8 8B 45 F8 29 45 FC 83 C4 0C 39 75 F4 75 11 57 E8 D3 F9 FF FF 85 C0 59 74 06 8B 45 F0 89 45 F4 8B 45 F8 01 45 F0 39 75 FC }
	$a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 80 3E 20 75 07 56 FF D7 8B F0 EB F4 80 3E 2F 75 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule VxGRUNT1Family
{
strings:
		$a0 = { 01 B9 ?? 00 31 17 }

condition:
		$a0 at entrypoint
}
	
	
rule BobSoftMiniDelphiBoBBobSoft
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 }
	$a1 = { 55 8B EC 83 C4 F0 53 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 ?? ?? ?? ?? E8 }
	$a2 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule UltraProV10SafeNet
{
strings:
		$a0 = { A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv1242v1243
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01PECompact14
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

condition:
		$a0 at entrypoint
}
	
	
rule ZipWorxSecureEXE25ZipWORXTechnologiesLLCh
{
strings:
		$a0 = { E9 B8 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30 }

condition:
		$a0
}
	
	
rule SimplePack121build0909Method2bagie
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 8A 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule DualsCryptordual
{
strings:
		$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium13037ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VxPhoenix927
{
strings:
		$a0 = { E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule Petite14c199899IanLuck
{
strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02PEX099
{
strings:
		$a0 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressorV10CGSoftLabs
{
strings:
		$a0 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PassEXEv20
{
strings:
		$a0 = { 06 1E 0E 0E 07 1F BE ?? ?? B9 ?? ?? 87 14 81 ?? ?? ?? EB ?? C7 ?? ?? ?? 84 00 87 ?? ?? ?? FB 1F 58 4A }

condition:
		$a0 at entrypoint
}
	
	
rule Mew501NorthFoxHCC
{
strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D }

condition:
		$a0 at entrypoint
}
	
	
rule PEiDBundleV100BoBBobSoft
{
strings:
		$a0 = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01ExeSmasherAnorganix
{
strings:
		$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02CrunchPEHeuristic
{
strings:
		$a0 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UnnamedScrambler12C12Dp0ke
{
strings:
		$a0 = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? 3A ?? ?? E8 ?? EC FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8 ?? D7 FF FF E8 ?? ?? FF FF B8 20 ?? ?? ?? 33 C9 BA 04 01 00 00 E8 ?? DB FF FF 68 04 01 00 00 68 20 ?? ?? ?? 6A 00 FF 15 10 }
	$a1 = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? 3A ?? ?? E8 ?? EC FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8 ?? D7 FF FF E8 ?? ?? FF FF B8 20 ?? ?? ?? 33 C9 BA 04 01 00 00 E8 ?? DB FF FF 68 04 01 00 00 68 20 ?? ?? ?? 6A 00 FF 15 10 ?? ?? ?? BA ?? ?? ?? ?? B8 14 ?? ?? ?? E8 ?? ?? FF FF 85 C0 0F 84 ?? 04 00 00 BA 18 ?? ?? ?? 8B 0D 14 ?? ?? ?? E8 ?? ?? FF FF 8B 05 88 ?? ?? ?? 8B D0 B8 54 ?? ?? ?? E8 ?? E3 FF FF B8 54 ?? ?? ?? E8 ?? E2 FF FF 8B D0 B8 18 ?? ?? ?? 8B 0D 88 ?? ?? ?? E8 ?? D6 FF FF FF 35 34 ?? ?? ?? FF 35 30 ?? ?? ?? FF 35 3C ?? ?? ?? FF 35 38 ?? ?? ?? 8D 55 E8 A1 88 ?? ?? ?? E8 ?? F0 FF FF 8B 55 E8 B9 54 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule AlexProtectorv04beta1byAlex
{
strings:
		$a0 = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 00 00 00 00 49 E8 01 00 00 00 68 83 C4 04 85 C9 75 DF E8 B9 02 00 00 E8 01 00 00 00 C7 83 C4 04 8D 95 63 14 40 00 E8 01 00 00 00 C7 83 C4 04 90 90 90 E8 CA 01 00 00 01 02 03 04 05 68 90 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UG2002Cruncherv03b3
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 }

condition:
		$a0 at entrypoint
}
	
	
rule FishPEShield101HellFish
{
strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 }
	$a1 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 AD FF FF FF 89 45 DC E8 C1 FE FF FF 8B 10 03 55 DC 89 55 E4 83 C0 04 8B 10 89 55 FC 83 C0 04 8B 10 89 55 F4 83 C0 04 8B 10 89 55 F8 83 C0 04 8B 10 89 55 F0 83 C0 04 8B 10 89 55 EC 83 C0 04 8B 00 89 45 E8 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B 46 C7 45 E0 00 00 00 00 83 7B 04 00 74 14 }
	$a2 = { 60 E8 12 FE FF FF C3 90 09 00 00 00 2C 00 00 00 }
	$a3 = { 60 E8 12 FE FF FF C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 28 88 00 00 40 ?? 4B 00 00 00 02 00 00 00 A0 00 00 18 01 00 00 40 ?? 4C 00 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 40 ?? 4E 00 00 00 00 00 00 00 C0 00 00 40 39 00 00 40 ?? 4E 00 00 00 08 00 00 00 00 01 00 C8 06 00 00 40 }

condition:
		$a0 or $a1 or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule PseudoSigner01Neolite20Anorganix
{
strings:
		$a0 = { E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PEIntrov10
{
strings:
		$a0 = { 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48 }

condition:
		$a0 at entrypoint
}
	
	
rule DevC4992BloodshedSoftware
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D }

condition:
		$a0 at entrypoint
}
	
	
rule UPolyXV01Delikon
{
strings:
		$a0 = { E2 ?? FF ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule XJXPALLiNSoN
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C }

condition:
		$a0 at entrypoint
}
	
	
rule MacromediaWindowsFlashProjectorPlayer50
{
strings:
		$a0 = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 }

condition:
		$a0
}
	
	
rule MingWin32DevCv4991h
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 ?? ?? 00 00 90 90 90 90 90 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov220b1
{
strings:
		$a0 = { 55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor20Vaska
{
strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv101b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }

condition:
		$a0 at entrypoint
}
	
	
rule HardlockdongleAlladin
{
strings:
		$a0 = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76 }

condition:
		$a0 at entrypoint
}
	
	
rule FSG120EngdulekxtBorlandDelphiMicrosoftVisualC
{
strings:
		$a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }

condition:
		$a0
}
	
	
rule SentinelSuperProAutomaticProtectionv641Safenet
{
strings:
		$a0 = { A1 ?? ?? ?? ?? 55 8B ?? ?? ?? 85 C0 74 ?? 85 ED 75 ?? A1 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 55 51 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 15 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 01 00 00 00 5D C2 0C 00 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 25 FE FF DF 3F 0D 01 00 20 00 A3 ?? ?? ?? ?? 33 C0 50 C7 04 ?? ?? ?? ?? ?? 00 00 00 00 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule TMTPascalv040
{
strings:
		$a0 = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9 }

condition:
		$a0 at entrypoint
}
	
	
rule VMProtect0xPolyTech
{
strings:
		$a0 = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPackerv100DLLLZBRS
{
strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 1C 00 00 00 72 03 A4 EB F2 E8 1A 00 00 00 8D 51 FF E8 12 00 00 00 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }
	$a1 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule VcAsmProtectorV10XVcAsm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor1451CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D 10 ?? ?? 00 00 74 16 A1 08 ?? ?? 00 8B 0D 0C ?? ?? 00 03 48 14 }
	$a1 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D 10 ?? ?? 00 00 74 16 A1 08 ?? ?? 00 8B 0D 0C ?? ?? 00 03 48 14 89 4D CC E9 97 04 00 00 C7 05 10 ?? ?? 00 01 00 00 00 ?? ?? 68 54 ?? ?? 00 68 18 ?? ?? 00 6A 00 FF 15 E4 ?? ?? 00 83 7D 0C 01 74 04 83 65 08 00 6A 04 68 00 10 00 00 68 04 01 00 00 6A 00 FF 15 C4 ?? ?? 00 89 45 EC 68 04 01 00 00 FF 75 EC FF 75 08 FF 15 DC ?? ?? 00 8B 4D EC 8D 44 01 FF 89 45 AC 8B 45 AC 0F BE 00 83 F8 5C 74 09 8B 45 AC 48 89 45 AC EB EC 8B 45 AC 40 89 45 AC 8B 45 AC 2B 45 EC 89 45 B0 6A 04 68 00 10 00 00 68 04 01 00 00 6A 00 FF 15 C4 ?? ?? 00 89 45 FC 8B 4D B0 8B 75 EC 8B 7D FC 8B C1 C1 E9 02 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule nSPack2xNorthStarLiuXingPing
{
strings:
		$a0 = { FF FF 8B 4E 08 8D 56 10 8B 36 8B FE 83 F9 00 74 3F 8A 07 47 2C E8 3C 01 77 F7 8B 07 80 7A 01 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualC
{
strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 D6 83 C7 32 F7 DA 03 FE EB 02 CD 20 87 FA 88 10 EB 02 CD 20 40 E8 02 00 00 00 F1 F8 5B 4E 2B D2 85 F6 75 AF EB 02 DE 09 EB 01 EF 34 4A 7C BC 7D 3D 7F 90 C1 82 41 ?? ?? ?? 87 DB 71 94 8B 8C 8D 90 61 05 96 1C A9 DA A7 68 5A 4A 19 CD 76 40 50 A0 9E B4 C5 15 9B D7 6E A5 BB CC 1C C2 DE 6C AC C2 D3 23 D2 65 B5 F5 65 C6 B6 CC DD CC 7B 2F B6 33 FE 6A AC 9E AB 07 C5 C6 C7 F3 94 3F DB B4 05 CE CF D0 BC FA 7F A5 BD 4A 18 EB A2 C5 F7 6D 25 9F BF E8 8D CA 05 E4 E5 E6 24 E8 66 EA EB 5F F7 6E EB F5 64 F8 76 EC 74 6D F9 }
	$a1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule InterplaysMVEfile
{
strings:
		$a0 = { 49 6E 74 65 72 70 6C 61 79 20 4D 56 45 20 46 69 6C 65 1A 00 1A }

condition:
		$a0
}
	
	
rule VxHafen809
{
strings:
		$a0 = { E8 ?? ?? 1C ?? 81 EE ?? ?? 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 ?? ?? ?? 07 3D }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01LTC13Anorganix
{
strings:
		$a0 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule RODHighTECHAyman
{
strings:
		$a0 = { 60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule tElock096tE
{
strings:
		$a0 = { E9 59 E4 FF FF 00 00 00 00 00 00 00 ?? ?? ?? ?? EE ?? ?? 00 00 00 00 00 00 00 00 00 0E ?? ?? 00 FE ?? ?? 00 F6 ?? ?? 00 00 00 00 00 00 00 00 00 1B ?? ?? 00 06 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C }

condition:
		$a0 at entrypoint
}
	
	
rule WerusCrypter10byKas
{
strings:
		$a0 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePEX099emadicius
{
strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 }

condition:
		$a0
}
	
	
rule UPXv051
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 D8 01 ?? ?? 83 CD FF 31 DB ?? ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90 }

condition:
		$a0 at entrypoint
}
	
	
rule LatticeCv30
{
strings:
		$a0 = { FA B8 ?? ?? 8E D8 B8 ?? ?? 8E }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack3xLiuXingPing
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D }

condition:
		$a0 at entrypoint
}
	
	
rule HEALTHv51byMuslimMPolyak
{
strings:
		$a0 = { 1E E8 ?? ?? 2E 8C 06 ?? ?? 2E 89 3E ?? ?? 8B D7 B8 ?? ?? CD 21 8B D8 0E 1F E8 ?? ?? 06 57 A1 ?? ?? 26 }

condition:
		$a0 at entrypoint
}
	
	
rule UPX302
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftWindowsUpdateCABSFXmodule
{
strings:
		$a0 = { E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18 }
	$a1 = { E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18 8B 55 20 89 50 1C 8B 55 24 89 50 20 8B 55 28 89 48 48 89 48 44 89 48 4C B9 FF FF 00 00 89 70 08 89 10 66 C7 80 B2 00 00 00 0F 00 89 88 A0 00 00 00 89 88 A8 00 00 00 89 88 A4 00 00 }

condition:
		$a0 or $a1
}
	
	
rule aPackv098bexe
{
strings:
		$a0 = { 93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA }

condition:
		$a0
}
	
	
rule MSLRH032afakeASPack212emadicius
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 73 00 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B }
	$a1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule PseudoSigner02VideoLanClient
{
strings:
		$a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 }

condition:
		$a0 at entrypoint
}
	
	
rule VxNovember17768
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoTinyPascalBeRo
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20 }

condition:
		$a0 at entrypoint
}
	
	
rule PUNiSHER15DEMOFEUERRADERAHTeam
{
strings:
		$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 }

condition:
		$a0
}
	
	
rule UPXv0896v102v105v122DLL
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

condition:
		$a0 at entrypoint
}
	
	
rule HASPHLProtection1XAladdin
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 }

condition:
		$a0
}
	
	
rule EPExEPackV14litefinal6aHguTgluk
{
strings:
		$a0 = { 90 90 90 90 61 B8 ?? ?? ?? ?? FF E0 55 8B EC 60 55 8B 75 08 8B 7D 0C E8 02 00 00 00 EB 04 8B 1C 24 C3 81 C3 00 02 00 00 53 57 8B 07 89 03 83 C7 04 83 C3 04 4E 75 F3 5F 5E FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 46 12 D2 73 EF 02 D2 75 05 8A 16 46 12 }

condition:
		$a0 at entrypoint
}
	
	
rule Trivial173bySMTSMF
{
strings:
		$a0 = { EB ?? ?? 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29 }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtectv11MTE
{
strings:
		$a0 = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PiCryptor10byScofield
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF }
	$a1 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 }
	$a2 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 5A 59 59 64 89 10 68 3D 1F 06 00 8D 45 EC E8 C3 F6 FF FF C3 }
	$a3 = { 89 55 F8 BB 01 00 00 00 8A 04 1F 24 0F 8B 55 FC 8A 14 32 80 E2 0F 32 C2 8A 14 1F 80 E2 F0 02 D0 88 14 1F 46 8D 45 F4 8B 55 FC E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B F0 7E 05 BE 01 00 00 00 43 FF 4D F8 75 C2 ?? ?? ?? ?? 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? C3 E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3
}
	
	
rule MSLRH032afakeASPack211demadicius
{
strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 }

condition:
		$a0
}
	
	
rule UPXSCRAMBLER306COnTRoL
{
strings:
		$a0 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }

condition:
		$a0 at entrypoint
}
	
	
rule WinZipSelfExtractor22personaleditionWinZipComputingh
{
strings:
		$a0 = { 53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B }

condition:
		$a0 at entrypoint
}
	
	
rule PEArmor07600765hying
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 00 08 00 00 00 00 00 00 00 60 E8 00 00 00 00 }

condition:
		$a0
}
	
	
rule PasswordProtectorfortheUPX030g0d
{
strings:
		$a0 = { C8 50 01 00 60 E8 EC 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 44 69 61 6C 6F 67 42 6F 78 49 6E 64 69 72 65 63 74 50 61 72 61 6D 41 00 53 65 6E 64 4D 65 73 73 61 67 65 41 00 45 6E 64 44 69 61 6C 6F }

condition:
		$a0 at entrypoint
}
	
	
rule PECryptv102
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }

condition:
		$a0
}
	
	
rule ILUCRYPTv4015exe
{
strings:
		$a0 = { 8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV118BasicEditionaPlib043ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualC60SFXCustom
{
strings:
		$a0 = { E8 21 48 00 00 E9 16 FE FF FF 51 C7 01 08 B4 00 30 E8 A4 48 00 00 59 C3 56 8B F1 E8 EA FF FF FF F6 ?? ?? ?? ?? 74 07 56 E8 F6 04 00 00 59 8B C6 5E C2 04 00 8B 44 24 04 83 C1 09 51 83 C0 09 50 }

condition:
		$a0 at entrypoint
}
	
	
rule MPEGmoviefile
{
strings:
		$a0 = { 00 00 01 BA 2F FF FD E6 C1 80 18 61 00 00 01 BB }

condition:
		$a0
}
	
	
rule NJoy13NEX
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 48 36 40 00 E8 54 EE FF FF 6A 00 68 D8 2B 40 00 6A 0A 6A 00 E8 2C EF FF FF E8 23 E7 FF FF 8D 40 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VBOXv43v46
{
strings:
		$a0 = { 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 }
	$a1 = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
	$a2 = { 90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 ?? ?? 2B C5 48 ?? ?? 0B C0 86 E0 8C E0 ?? ?? 8C E0 86 E0 03 C4 40 }

condition:
		$a0 or $a1 or $a2
}
	
	
rule CodeLockvxx
{
strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 }

condition:
		$a0 at entrypoint
}
	
	
rule CipherWallSelfExtratorDecryptorGUIv15
{
strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 52 10 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 0E 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 }

condition:
		$a0 at entrypoint
}
	
	
rule ARMProtectorv01bySMoKE
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }

condition:
		$a0
}
	
	
rule PseudoSigner02PENightMare2Beta
{
strings:
		$a0 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

condition:
		$a0 at entrypoint
}
	
	
rule hyingsPEArmorhyingCCG
{
strings:
		$a0 = { E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D }

condition:
		$a0 at entrypoint
}
	
	
rule Anti007NsPacKPrivate
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXwwwupxsourceforgenet
{
strings:
		$a0 = { 60 BE ?? ?0 4? 00 8D BE ?? ?? F? FF }
	$a1 = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF }

condition:
		$a0 or $a1
}
	
	
rule Upackv037betaDwing
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 8E FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F }

condition:
		$a0 at entrypoint
}
	
	
rule PrivateExeProtector1xsetisoft
{
strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 ?? ?? ?? C3 }

condition:
		$a0 at entrypoint
}
	
	
rule Petitev14
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }

condition:
		$a0 at entrypoint
}
	
	
rule NullsoftInstallSystemv20a0
{
strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 }

condition:
		$a0
}
	
	
rule VPackerttui
{
strings:
		$a0 = { 89 C6 C7 45 E0 01 00 00 00 F7 03 00 00 FF FF 75 18 0F B7 03 50 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 EB 13 53 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 83 C7 04 FF 45 E0 4E 75 C4 8B F3 83 3E 00 75 88 8B 45 E4 8B 40 10 03 45 DC }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium1332ObsidiumSoftware
{
strings:
		$a0 = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 }
	$a1 = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 3B 27 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule modifiedHACKSTOPv111f
{
strings:
		$a0 = { 52 B4 30 CD 21 52 FA ?? FB 3D ?? ?? EB ?? CD 20 0E 1F B4 09 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtectorV11XRandyLiSignbyfly
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 }

condition:
		$a0 at entrypoint
}
	
	
rule RLPackV119LZMA430ap0xnbspnbspSignbyfly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule VxCIHVersion12TTITWIN95CIH
{
strings:
		$a0 = { 55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D }

condition:
		$a0 at entrypoint
}
	
	
rule PohernahCrypterV101Kas
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24 }

condition:
		$a0 at entrypoint
}
	
	
rule ShegerdDongleV478MSCo
{
strings:
		$a0 = { E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtectRandyLi
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? 00 00 00 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule PseudoSigner02CDCopsII
{
strings:
		$a0 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2021wwwstrongbitcom
{
strings:
		$a0 = { 55 8B EC 83 C4 F4 56 57 53 BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW32xDll_WinMain
{
strings:
		$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 }

condition:
		$a0
}
	
	
rule SmokesCryptv12
{
strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }

condition:
		$a0 at entrypoint
}
	
	
rule PEncryptv31
{
strings:
		$a0 = { E9 ?? ?? ?? 00 F0 0F C6 }

condition:
		$a0 at entrypoint
}
	
	
rule PEncryptv30
{
strings:
		$a0 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB ?? ?? ?? ?? AD 33 C3 E2 FA }

condition:
		$a0 at entrypoint
}
	
	
rule RJoiner12byVaska250320071658
{
strings:
		$a0 = { 55 8B EC 81 EC 0C 02 00 00 8D 85 F4 FD FF FF 56 50 68 04 01 00 00 FF 15 14 10 40 00 90 8D 85 F4 FD FF FF 50 FF 15 10 10 40 00 90 BE 00 20 40 00 90 83 3E FF 0F 84 84 00 00 00 53 57 33 FF 8D 46 }

condition:
		$a0 at entrypoint
}
	
	
rule pexV099params
{
strings:
		$a0 = { E9 F5 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule v02Packerttt
{
strings:
		$a0 = { 60 E8 36 FE FF FF C3 90 ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule NakedPackerV10BigBoote
{
strings:
		$a0 = { 60 FC 0F B6 05 ?? ?? ?? ?? 85 C0 75 31 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9A 00 00 00 A3 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 83 3D ?? ?? ?? ?? 00 75 07 61 FF 25 ?? ?? ?? ?? 61 FF 74 24 04 6A 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Minke101byCodius
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 ?? ?? ?? ?? ?? 10 E8 7A F6 FF FF BE 68 66 00 10 33 C0 55 68 DB 40 00 10 64 FF 30 64 89 20 E8 FA F8 FF FF BA EC 40 00 10 8B C6 E8 F2 FA FF FF 8B D8 B8 6C 66 00 10 8B 16 E8 88 F2 FF FF B8 6C 66 00 10 E8 76 F2 FF FF 8B D0 8B C3 8B 0E E8 }
	$a1 = { 55 8B EC 83 C4 F0 53 ?? ?? ?? ?? ?? 10 E8 7A F6 FF FF BE 68 66 00 10 33 C0 55 68 DB 40 00 10 64 FF 30 64 89 20 E8 FA F8 FF FF BA EC 40 00 10 8B C6 E8 F2 FA FF FF 8B D8 B8 6C 66 00 10 8B 16 E8 88 F2 FF FF B8 6C 66 00 10 E8 76 F2 FF FF 8B D0 8B C3 8B 0E E8 E3 E4 FF FF E8 2A F9 FF FF E8 C1 F8 FF FF B8 6C 66 00 10 8B 16 E8 6D FA FF FF E8 14 F9 FF FF E8 AB F8 FF FF 8B 06 E8 B8 E3 FF FF 8B D8 B8 6C 66 00 10 E8 38 F2 FF FF 8B D3 8B 0E E8 A7 E4 FF ?? ?? ?? ?? C4 FB FF FF E8 E7 F8 FF FF 8B C3 E8 B0 E3 FF FF E8 DB F8 FF FF 33 C0 5A 59 59 64 89 10 68 E2 40 00 10 C3 E9 50 EB FF FF EB F8 5E 5B E8 BB EF FF FF 00 00 00 43 41 31 38 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PseudoSigner02MicrosoftVisualBasic5060
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule CrypWrapvxx
{
strings:
		$a0 = { E8 B8 ?? ?? ?? E8 90 02 ?? ?? 83 F8 ?? 75 07 6A ?? E8 ?? ?? ?? ?? FF 15 49 8F 40 ?? A9 ?? ?? ?? 80 74 0E }

condition:
		$a0 at entrypoint
}
	
	
rule PhoenixProtectorv10v11NTCorecom
{
strings:
		$a0 = { 02 6F ?? ?? ?? 0A 0A 06 8D ?? ?? ?? 01 0B 16 0C 38 36 00 00 00 02 08 6F ?? ?? ?? 0A 0D 09 06 08 59 61 D2 13 04 09 1E 63 08 61 D2 13 05 07 08 11 05 1E 62 11 04 60 D1 9D 08 17 58 0C 08 07 8E 69 38 0B 00 00 00 28 ?? ?? ?? 0A 2A 38 EC FF FF FF 3F C0 FF FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftVisualC50
{
strings:
		$a0 = { 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57 }

condition:
		$a0
}
	
	
rule WarningmaybeSimbyOZpolycryptorby3xpl01tver2xx250320072200
{
strings:
		$a0 = { 57 57 8D 7C 24 04 50 B8 00 D0 17 13 AB 58 5F C3 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule TrueTypeFontfile
{
strings:
		$a0 = { 00 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 4C 54 53 48 }
	$a1 = { 00 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 4F 53 2F 32 }

condition:
		$a0 or $a1
}
	
	
rule PseudoSigner02LocklessIntroPack
{
strings:
		$a0 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack116aPLibcompressionap0xh
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 53 03 00 00 8D 9D 02 02 00 00 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 E8 02 00 00 89 85 4F 03 00 00 5B FF B5 4F 03 00 00 56 FF D3 83 C4 08 8B B5 4F 03 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 E8 CD 00 00 00 83 C0 04 89 85 4B 03 00 00 E9 93 00 00 00 56 FF 95 E0 02 00 00 85 C0 0F 84 AE 00 00 00 89 85 47 03 00 00 8B C6 EB 5B 8B 85 4B 03 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 4B 03 00 00 C7 00 20 20 20 00 EB 06 FF B5 4B 03 00 00 FF B5 47 03 00 00 FF 95 E4 02 00 00 85 C0 74 6B 89 07 83 C7 04 8B }

condition:
		$a0
}
	
	
rule EPv10
{
strings:
		$a0 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 C0 30 ?? 68 ?? ?? F3 00 C3 AA }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH032afakePELockNT204emadicius
{
strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 EB EB 03 CD 20 03 61 9D 83 C4 04 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 }

condition:
		$a0
}
	
	
rule FSG110EngdulekxtBorlandDelphiMicrosoftVisualC
{
strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }

condition:
		$a0 at entrypoint
}
	
	
rule EP10
{
strings:
		$a0 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 }

condition:
		$a0
}
	
	
rule PROPACKv208
{
strings:
		$a0 = { 8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53 }

condition:
		$a0 at entrypoint
}
	
	
rule Upackv024v028alphaSignbyhot_UNP
{
strings:
		$a0 = { BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD }

condition:
		$a0 at entrypoint
}
	
	
rule BlackEnergyDDoSBotCrypter
{
strings:
		$a0 = { 55 ?? ?? 81 EC 1C 01 00 00 53 56 57 6A 04 BE 00 30 00 00 56 FF 35 00 20 11 13 6A 00 E8 ?? 03 00 00 ?? ?? 83 C4 10 ?? FF 89 7D F4 0F }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOPv113
{
strings:
		$a0 = { 52 B8 ?? ?? 1E CD 21 86 E0 3D ?? ?? 73 ?? CD 20 0E 1F B4 09 E8 ?? ?? 24 ?? EA }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner151GlOFF
{
strings:
		$a0 = { 90 87 FF 90 90 B9 2B 00 00 00 BA 07 10 40 00 83 C2 03 90 87 FF 90 90 B9 04 00 00 00 90 87 FF 90 33 C9 C7 05 09 30 40 00 00 00 00 00 68 00 01 00 00 68 21 30 40 00 6A 00 E8 B7 02 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 21 30 40 00 E8 8F 02 00 00 A3 19 30 40 00 90 87 FF 90 8B 15 09 30 40 00 81 C2 04 01 00 00 F7 DA 6A 02 6A 00 52 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv098b2
{
strings:
		$a0 = { E9 1B E4 FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv098b1
{
strings:
		$a0 = { E9 25 E4 FF FF }

condition:
		$a0 at entrypoint
}
	
	
rule PeXv099EngbartCrackPl
{
strings:
		$a0 = { E9 F5 00 00 00 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 50 65 58 20 28 63 29 20 62 79 20 62 61 72 74 5E 43 72 61 63 6B 50 6C 20 62 65 74 61 20 72 65 6C 65 61 73 65 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 60 E8 01 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealth274
{
strings:
		$a0 = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 }

condition:
		$a0
}
	
	
rule HACKSTOPv119
{
strings:
		$a0 = { 52 BA ?? ?? 5A EB ?? 9A ?? ?? ?? ?? 30 CD 21 ?? ?? ?? D6 02 ?? ?? CD 20 0E 1F 52 BA ?? ?? 5A EB }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOPv118
{
strings:
		$a0 = { 52 BA ?? ?? 5A EB ?? 9A ?? ?? ?? ?? 30 CD 21 ?? ?? ?? FD 02 ?? ?? CD 20 0E 1F 52 BA ?? ?? 5A EB }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealth273
{
strings:
		$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 }

condition:
		$a0
}
	
	
rule Obsidium1333ObsidiumSoftwareSignByhaggar
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27 }

condition:
		$a0 at entrypoint
}
	
	
rule PEiDBundleV101BoBBobSoft
{
strings:
		$a0 = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITEv200c
{
strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 3B C4 73 ?? 8B C4 2D ?? ?? 25 ?? ?? 8B F8 B9 ?? ?? BE ?? ?? FC }

condition:
		$a0 at entrypoint
}
	
	
rule MEW11SE11Northfox
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 0C ?? ?? ?? 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule WWPACKv300v301Relocationspack
{
strings:
		$a0 = { BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC }

condition:
		$a0 at entrypoint
}
	
	
rule A3ETXT2COM
{
strings:
		$a0 = { 1E 33 C0 50 BE ?? ?? 81 C6 ?? ?? B8 ?? ?? 8E C0 BF ?? ?? B9 ?? ?? F3 A5 CB }

condition:
		$a0 at entrypoint
}
	
	
rule RARSFX
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 00 00 00 00 90 }

condition:
		$a0 at entrypoint
}
	
	
rule mPackV003DeltaAziz
{
strings:
		$a0 = { 55 8B EC 83 ?? ?? 33 C0 89 45 F0 B8 ?? ?? ?? ?? E8 67 C4 FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? E8 FA C9 FF FF 83 F8 FF }

condition:
		$a0 at entrypoint
}
	
	
rule WebCopsEXE
{
strings:
		$a0 = { EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72 }

condition:
		$a0 at entrypoint
}
	
	
rule VxCaz1204
{
strings:
		$a0 = { E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }

condition:
		$a0 at entrypoint
}
	
	
rule ZealPack10Zeal
{
strings:
		$a0 = { C7 45 F4 00 00 40 00 C7 45 F0 ?? ?? ?? ?? 8B 45 F4 05 ?? ?? ?? ?? 89 45 F4 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 F0 7D 22 8B 45 F4 03 45 FC 8A 08 88 4D F8 0F BE 55 F8 83 F2 0F 88 55 F8 8B 45 F4 03 45 FC 8A 4D F8 88 08 EB CD FF 65 F4 }

condition:
		$a0 at entrypoint
}
	
	
rule CPAV
{
strings:
		$a0 = { E8 ?? ?? 4D 5A B1 01 93 01 00 00 02 }

condition:
		$a0 at entrypoint
}
	
	
rule DiskDupecMSDUsersfile
{
strings:
		$a0 = { 4D 53 44 20 55 73 65 72 73 20 56 65 72 73 69 6F 6E }

condition:
		$a0
}
	
	
rule INCrypter03INinYbyz3e_NiFe
{
strings:
		$a0 = { 60 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8D 58 20 C7 03 00 00 00 00 E8 00 00 00 00 5D 81 ED 4D 16 40 00 8B 9D 0E 17 40 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 83 F8 01 75 05 03 DB C1 CB 10 8B 8D 12 17 40 00 8B B5 06 17 40 00 51 81 3E 2E 72 73 72 74 65 8B }
	$a1 = { 60 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8D 58 20 C7 03 00 00 00 00 E8 00 00 00 00 5D 81 ED 4D 16 40 00 8B 9D 0E 17 40 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 83 F8 01 75 05 03 DB C1 CB 10 8B 8D 12 17 40 00 8B B5 06 17 40 00 51 81 3E 2E 72 73 72 74 65 8B 85 16 17 40 00 E8 23 00 00 00 8B 85 1A 17 40 00 E8 18 00 00 00 8B 85 1E 17 40 00 E8 0D 00 00 00 8B 85 22 17 40 00 E8 02 00 00 00 EB 18 8B D6 3B 46 0C 72 0A 83 F9 01 74 0B 3B 46 34 72 06 BA 00 00 00 00 C3 58 83 FA 00 75 1A 8B 4E 10 8B 7E 0C 03 BD 02 17 40 00 83 F9 00 74 09 F6 17 31 0F 31 1F 47 E2 F7 59 83 C6 28 49 83 F9 00 75 88 8B 85 0A 17 40 00 89 44 24 1C 61 50 C3 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule nBinderv361
{
strings:
		$a0 = { 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C 00 5C 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C }

condition:
		$a0
}
	
	
rule MatrixDongleTDiGmbH
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 E8 B6 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? E8 00 00 00 00 5B 2B D9 8B F8 8B 4C 24 2C 33 C0 2B CF F2 AA 8B 3C 24 8B 0A 2B CF 89 5C 24 20 80 37 A2 47 49 75 F9 8D 64 24 04 FF 64 24 FC 60 C7 42 08 ?? ?? ?? ?? E8 C5 FF FF FF C3 C2 F7 29 4E 29 5A 29 E6 86 8A 89 63 5C A2 65 E2 A3 A2 }
	$a1 = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF }

condition:
		$a0 or $a1 at entrypoint
}
	
	
rule NullsoftInstallSystemv20RC2
{
strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D3 E8 6A FF FF FF 85 C0 0F 84 59 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 B9 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 40 43 00 8B 3D 18 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52 }

condition:
		$a0
}
	
	
rule MicrosoftVisualCv7064Bit
{
strings:
		$a0 = { 41 00 00 00 00 00 00 00 63 00 00 00 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 20 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 }
	$a1 = { 41 00 00 00 00 00 00 00 63 00 00 00 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 20 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule MinGWGCCv2x
{
strings:
		$a0 = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACKv305c4UnextractablePasswordchecking
{
strings:
		$a0 = { 03 05 80 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo4000053SiliconRealmsToolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1 }

condition:
		$a0
}
	
	
rule FSG120EngdulekxtMASM32TASM32
{
strings:
		$a0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }

condition:
		$a0
}
	
	
rule fds0ftc0mpr0tectv04b
{
strings:
		$a0 = { 8C CA 2E ?? ?? ?? ?? B4 30 8B ?? ?? ?? 8B ?? ?? ?? 8E DA A3 ?? ?? 8C ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandDelphiSetupModule
{
strings:
		$a0 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 }

condition:
		$a0 at entrypoint
}
	
	
rule FSGv110EngdulekxtBorlandDelphi20
{
strings:
		$a0 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }

condition:
		$a0 at entrypoint
}
	
	
rule Reg2Exe225byJanVorel
{
strings:
		$a0 = { 68 68 00 00 00 68 00 00 00 00 68 70 7D 40 00 E8 AE 20 00 00 83 C4 0C 68 00 00 00 00 E8 AF 52 00 00 A3 74 7D 40 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 9C 52 00 00 A3 70 7D 40 00 E8 24 50 00 00 E8 E2 48 00 00 E8 44 34 00 00 E8 54 28 00 00 E8 98 }
	$a1 = { 68 68 00 00 00 68 00 00 00 00 68 70 7D 40 00 E8 AE 20 00 00 83 C4 0C 68 00 00 00 00 E8 AF 52 00 00 A3 74 7D 40 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 9C 52 00 00 A3 70 7D 40 00 E8 24 50 00 00 E8 E2 48 00 00 E8 44 34 00 00 E8 54 28 00 00 E8 98 27 00 00 E8 93 20 00 00 68 01 00 00 00 68 D0 7D 40 00 68 00 00 00 00 8B 15 D0 7D 40 00 E8 89 8F 00 00 B8 00 00 10 00 68 01 00 00 00 E8 9A 8F 00 00 FF 35 A4 7F 40 00 68 00 01 00 00 E8 3A 23 00 00 8D 0D A8 7D 40 00 5A E8 5E 1F 00 00 FF 35 A8 7D 40 00 68 00 01 00 00 E8 2A 52 00 00 A3 B4 7D 40 00 FF 35 A4 7F 40 00 FF 35 B4 7D 40 00 FF 35 A8 7D 40 00 E8 5C 0C 00 00 8D 0D A0 7D 40 00 5A E8 26 1F 00 00 FF 35 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MicrosoftVisualCv50
{
strings:
		$a0 = { 55 8B EC 6A FF 68 68 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 53 56 57 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv160v165
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }

condition:
		$a0 at entrypoint
}
	
	
rule ThinstallEmbeddedV20XJitit
{
strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov420SiliconRealmsToolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 F0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 84 A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 80 A5 4C 00 C1 E1 08 03 CA 89 0D 7C A5 4C 00 C1 E8 10 A3 78 A5 4C 00 33 F6 56 E8 78 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 43 13 00 00 FF 15 8C 30 4C 00 A3 84 BB 4C 00 E8 01 12 00 00 A3 D8 A5 4C 00 E8 AA 0F 00 00 E8 EC 0E 00 00 E8 2D FA FF FF 89 }

condition:
		$a0
}
	
	
rule DalKrypt10byDalKiT
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 58 68 ?? ?? ?? 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? 00 72 EB FF E7 }
	$a1 = { 68 00 10 40 00 58 68 ?? ?? ?? 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? 00 72 EB FF E7 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RCryptorv15Vaska
{
strings:
		$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F }

condition:
		$a0 at entrypoint
}
	
	
rule NSPackNortStarSoftwareurlwwwnsdsncom
{
strings:
		$a0 = { 83 F9 00 74 28 43 8D B5 ?? ?? FF FF 8B 16 56 51 53 52 56 FF 33 FF 73 04 8B 43 08 03 C2 50 FF 95 ?? ?? FF FF 5A 5B 59 5E 83 C3 0C E2 E1 61 9D E9 ?? ?? ?? FF 8B B5 ?? ?? FF FF 0B F6 0F 84 97 00 00 00 8B 95 ?? ?? FF FF 03 F2 83 3E 00 75 0E 83 7E 04 00 75 08 83 7E 08 00 75 02 EB 7A 8B 5E 08 03 DA 53 52 56 8D BD ?? ?? FF FF 03 7E 04 83 C6 0C 57 }

condition:
		$a0 at entrypoint
}
	
	
rule PESpinv03Cyberbobh
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor239compressedresources
{
strings:
		$a0 = { 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 ?? ?? ?? ?? 00 00 23 C1 81 E9 ?? ?? ?? ?? 57 E9 ED 00 00 00 0F 88 ?? ?? ?? ?? E9 2C 0D 00 00 81 ED BB 43 CB 79 C1 E0 1C E9 9E 14 00 00 0B 15 ?? ?? ?? ?? 81 E2 2A 70 7F 49 81 C2 9D 83 12 3B E8 0C 50 00 00 E9 A0 16 00 00 59 5B C3 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 41 42 00 00 E9 93 33 00 00 31 DB 89 D8 59 5B C3 A1 ?? ?? ?? ?? 8A 00 2C 99 E9 82 30 00 00 0F 8A ?? ?? ?? ?? B8 01 00 00 00 31 D2 0F A2 25 FF 0F 00 00 E9 72 21 00 00 0F 86 57 0B 00 00 E9 ?? ?? ?? ?? C1 C0 03 E8 F0 36 00 00 E9 41 0A 00 00 81 F7 B3 6E 85 EA 81 C7 ?? ?? ?? ?? 87 3C 24 E9 74 52 00 00 0F 8E ?? ?? ?? ?? E8 5E 37 00 00 68 B1 74 96 13 5A E9 A1 04 00 00 81 D1 49 C0 12 27 E9 50 4E 00 00 C1 C8 1B 1B C3 81 E1 96 36 E5 }

condition:
		$a0 at entrypoint
}
	
	
rule MSVCDLLv8typicalOEPrecognizedh
{
strings:
		$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? ?? ?? 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 ?? ?? ?? FF 85 C0 75 04 33 C0 EB 4E 57 56 53 E8 ?? ?? ?? FF 83 FE 01 89 45 0C 75 0C 85 C0 75 37 57 50 53 E8 ?? ?? ?? FF 85 F6 74 05 83 FE 03 75 26 57 56 53 E8 ?? ?? ?? FF 85 C0 75 03 21 45 0C 83 7D 0C 00 74 11 A1 ?? ?? ?? ?? 85 C0 74 08 57 56 53 FF D0 89 45 0C 8B 45 0C 5F 5E 5B 5D C2 0C 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall2403Jitit
{
strings:
		$a0 = { 6A 00 FF 15 20 50 40 00 E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }

condition:
		$a0
}
	
	
rule RCryptorV15VaskaSignbyfly
{
strings:
		$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? ?? EB F3 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 at entrypoint
}
	
	
rule FreePascalv09910
{
strings:
		$a0 = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }

condition:
		$a0 at entrypoint
}
	
	
rule SoftDefender11xRandyLi
{
strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner0232Lite003Anorganix
{
strings:
		$a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 }

condition:
		$a0 at entrypoint
}
	
	
rule Apex_cbeta500mhz
{
strings:
		$a0 = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a1 = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PeCompact253DLLBitSumTechnologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 00 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector11A12vcasm
{
strings:
		$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F 32 30 30 35 5F 33 5F 31 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }

condition:
		$a0
}
	
	
rule codeCrypter031
{
strings:
		$a0 = { 50 58 53 5B 90 BB ?? ?? 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 }
	$a1 = { 50 58 53 5B 90 BB ?? ?? 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule Obsidium1339ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 }
	$a1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule TurboBATv31050Patched
{
strings:
		$a0 = { 90 90 90 90 90 90 90 06 B8 ?? ?? 8E C0 B9 ?? ?? 26 ?? ?? ?? ?? 80 ?? ?? 26 ?? ?? ?? 24 ?? 3A C4 90 90 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor2xxmaxcompressedresourceswwwstrongbitcomSignByhaggar
{
strings:
		$a0 = { 55 8B EC 83 C4 EC FC 53 57 56 89 45 FC 89 55 F8 89 C6 89 D7 66 81 3E 4A 43 0F 85 23 01 00 00 83 C6 0A C7 45 F4 08 00 00 00 31 DB BA 00 00 00 80 43 31 C0 E8 11 01 00 00 73 0E 8B 4D F0 E8 1F 01 00 00 02 45 EF AA EB E9 E8 FC 00 00 00 0F 82 97 00 00 00 E8 F1 00 00 00 73 5B B9 04 00 00 00 E8 FD 00 00 00 48 74 DE 0F 89 C7 00 00 00 E8 D7 00 00 00 73 1B 55 BD 00 01 00 00 E8 D7 00 00 00 88 07 47 4D 75 F5 E8 BF 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 C8 00 00 00 83 C0 07 89 45 F0 C6 45 EF 00 83 F8 08 74 89 E8 A9 00 00 00 88 45 EF E9 7C FF FF FF B9 07 00 00 00 E8 A2 00 00 00 50 }

condition:
		$a0
}
	
	
rule PKTINYv10withTINYPROGv38
{
strings:
		$a0 = { 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? E9 ?? ?? E8 ?? ?? 83 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandC
{
strings:
		$a0 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 05 2B CF FC F3 AA 59 5F }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV1333ObsidiumSoftware
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B ?? 24 0C EB 01 ?? 83 ?? B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }

condition:
		$a0 at entrypoint
}
	
	
rule USSRV031SpiritST
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 2E 55 53 53 52 00 00 00 00 10 00 00 ?? ?? ?? ?? 00 10 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 }

condition:
		$a0
}
	
	
rule InstallerVISECustom
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D }

condition:
		$a0 at entrypoint
}
	
	
rule unknownjac
{
strings:
		$a0 = { 55 89 E5 B9 00 80 00 00 BA ?? ?? ?? ?? B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 31 C2 66 01 C2 C1 C2 07 E2 F1 50 E8 91 FF FF FF C9 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule HyingsPEArmor075exeHyingCCG
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 ?? ?? 01 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 74 ?? ?? ?? 00 00 00 00 00 00 00 00 84 ?? ?? ?? 74 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 08 00 00 00 00 00 00 00 60 E8 00 00 00 00 5D 81 ED D7 00 00 00 8D B5 EE 00 00 00 55 56 81 C5 ?? ?? 00 00 55 C3 }
	$a1 = { 00 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 ?? ?? 01 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 74 ?? ?? ?? 00 00 00 00 00 }

condition:
		$a0 or $a1
}
	
	
rule PseudoSigner01Gleam100Anorganix
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9 }

condition:
		$a0 at entrypoint
}
	
	
rule UPXv0896v102v105v122Delphistub
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }

condition:
		$a0 at entrypoint
}
	
	
rule TheaPEInlinePatchBasicAdvancedStealth
{
strings:
		$a0 = { B9 ?? ?? ?? 00 E8 ?? ?? 00 00 89 01 68 }

condition:
		$a0 at entrypoint
}
	
	
rule UPX20030XMarkusOberhumerampLaszloMolnarampJohnReiser
{
strings:
		$a0 = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF ?? ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF ?? ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB E1 FF ?? ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? ?? ?? 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }

condition:
		$a0
}
	
	
rule PseudoSigner01MicrosoftVisualC50MFCAnorganix
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule Pohernah101byKas
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 38 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 14 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillov25xv26x
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtectv141
{
strings:
		$a0 = { 60 76 03 77 01 7B 74 03 75 01 78 47 87 EE E8 01 00 00 00 76 83 C4 04 85 EE EB 01 7F 85 F2 EB 01 79 0F 86 01 00 00 00 FC EB 01 78 79 02 87 F2 61 51 8F 05 19 38 01 01 60 EB 01 E9 E9 01 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule SimpleUPXCryptorv3042005multilayerencryption
{
strings:
		$a0 = { 60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
	$a1 = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ThemidaWinLicenseV1000V1800OreansTechnologiesSignbyfly
{
strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule Escargot01byueMeat
{
strings:
		$a0 = { EB 08 28 65 73 63 30 2E 31 29 60 68 2B ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 5C ?? ?? ?? 8B 00 FF D0 50 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B }
	$a1 = { EB 08 28 65 73 63 30 2E 31 29 60 68 2B ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 5C ?? ?? ?? 8B 00 FF D0 50 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 B8 54 ?? ?? ?? 8B 00 FF D0 5F 80 3F 00 74 06 C6 07 00 47 EB F5 33 FF 8B 16 0B D2 75 03 8B 56 10 03 D3 03 D7 8B 0A C7 02 00 00 00 00 0B C9 74 4B F7 C1 00 00 00 80 74 14 81 E1 FF FF 00 00 50 51 50 B8 50 }

condition:
		$a0 at entrypoint or $a1
}
	
	
rule FishPEV10XhellfishSignbyfly
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 ?? ?? 00 00 ?? ?? ?? ?? 00 00 02 00 00 00 A0 00 00 18 01 00 00 ?? ?? ?? ?? 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 C0 00 00 40 39 00 00 ?? ?? ?? ?? 00 00 08 00 00 00 00 01 00 C8 06 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule VMProtectv125PolyTech
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 }
	$a1 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 }
	$a2 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 }
	$a3 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 }
	$a4 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 }
	$a5 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A }
	$a6 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B }
	$a7 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 04 07 83 ED 02 66 89 45 00 E9 }
	$a8 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 55 00 83 C5 02 66 89 14 07 E9 }
	$a9 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 8B 55 00 83 C5 02 88 14 07 E9 }
	$a10 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 66 98 98 83 ED 04 89 45 00 E9 }
	$a11 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 83 ED 02 66 89 45 00 E9 }
	$a12 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 46 8A 04 07 83 ED 02 66 89 45 00 E9 }
	$a13 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 46 83 ED 02 66 89 45 00 E9 }
	$a14 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 C6 01 83 ED 02 66 89 45 00 E9 }
	$a15 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 46 66 89 45 00 E9 }
	$a16 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 46 E9 }
	$a17 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 83 C6 01 E9 }
	$a18 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 83 EE FF E9 }
	$a19 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 66 89 45 00 8D 76 01 E9 }
	$a20 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 83 C6 01 66 89 45 00 E9 }
	$a21 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 83 EE FF 66 89 45 00 E9 }
	$a22 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 ED 02 8D 76 01 66 89 45 00 E9 }
	$a23 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 83 EE FF 83 ED 02 66 89 45 00 E9 }
	$a24 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 04 07 8D 76 01 83 ED 02 66 89 45 00 E9 }
	$a25 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 46 83 C5 02 66 89 14 07 E9 }
	$a26 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 46 83 C5 02 88 14 07 E9 }
	$a27 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 46 66 89 14 07 E9 }
	$a28 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 46 88 14 07 E9 }
	$a29 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 46 E9 }
	$a30 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 83 C6 01 E9 }
	$a31 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 83 EE FF E9 }
	$a32 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 8D 76 01 E9 }
	$a33 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 C6 01 66 89 14 07 E9 }
	$a34 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 C6 01 88 14 07 E9 }
	$a35 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 EE FF 66 89 14 07 E9 }
	$a36 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 83 EE FF 88 14 07 E9 }
	$a37 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 46 E9 }
	$a38 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 83 C6 01 E9 }
	$a39 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 83 EE FF E9 }
	$a40 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 88 14 07 8D 76 01 E9 }
	$a41 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 8D 76 01 66 89 14 07 E9 }
	$a42 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 8D 76 01 88 14 07 E9 }
	$a43 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C6 01 83 C5 02 66 89 14 07 E9 }
	$a44 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C6 01 83 C5 02 88 14 07 E9 }
	$a45 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 EE FF 83 C5 02 66 89 14 07 E9 }
	$a46 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 EE FF 83 C5 02 88 14 07 E9 }
	$a47 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 8D 76 01 83 C5 02 66 89 14 07 E9 }
	$a48 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 8D 76 01 83 C5 02 88 14 07 E9 }
	$a49 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 46 98 83 ED 04 89 45 00 E9 }
	$a50 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 83 C6 01 98 83 ED 04 89 45 00 E9 }
	$a51 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 83 EE FF 98 83 ED 04 89 45 00 E9 }
	$a52 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 8D 76 01 98 83 ED 04 89 45 00 E9 }
	$a53 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 46 83 ED 04 89 45 00 E9 }
	$a54 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 C6 01 83 ED 04 89 45 00 E9 }
	$a55 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 46 89 45 00 E9 }
	$a56 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 83 C6 01 89 45 00 E9 }
	$a57 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 83 EE FF 89 45 00 E9 }
	$a58 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 46 E9 }
	$a59 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 83 C6 01 E9 }
	$a60 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 83 EE FF E9 }
	$a61 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 89 45 00 8D 76 01 E9 }
	$a62 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 ED 04 8D 76 01 89 45 00 E9 }
	$a63 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 83 EE FF 83 ED 04 89 45 00 E9 }
	$a64 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 98 98 8D 76 01 83 ED 04 89 45 00 E9 }
	$a65 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 04 07 83 ED 02 66 89 45 00 E9 }
	$a66 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 55 00 83 C5 02 66 89 14 07 E9 }
	$a67 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 8B 55 00 83 C5 02 88 14 07 E9 }
	$a68 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 66 98 98 83 ED 04 89 45 00 E9 }
	$a69 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 83 ED 02 66 89 45 00 E9 }
	$a70 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 C6 01 8A 04 07 83 ED 02 66 89 45 00 E9 }
	$a71 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 46 66 89 45 00 E9 }
	$a72 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 46 E9 }
	$a73 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 83 C6 01 E9 }
	$a74 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 83 EE FF E9 }
	$a75 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 66 89 45 00 8D 76 01 E9 }
	$a76 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 83 C6 01 66 89 45 00 E9 }
	$a77 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 83 EE FF 66 89 45 00 E9 }
	$a78 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 8D 76 01 66 89 45 00 E9 }
	$a79 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 04 07 83 ED 02 66 89 45 00 E9 }
	$a80 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 55 00 83 C5 02 66 89 14 07 E9 }
	$a81 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 8B 55 00 83 C5 02 88 14 07 E9 }
	$a82 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 66 98 98 83 ED 04 89 45 00 E9 }
	$a83 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 83 ED 02 66 89 45 00 E9 }
	$a84 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 EE FF 8A 04 07 83 ED 02 66 89 45 00 E9 }
	$a85 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 46 83 ED 02 66 89 45 00 E9 }
	$a86 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 C6 01 83 ED 02 66 89 45 00 E9 }
	$a87 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 46 66 89 45 00 E9 }
	$a88 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 46 E9 }
	$a89 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 83 C6 01 E9 }
	$a90 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 83 EE FF E9 }
	$a91 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 66 89 45 00 8D 76 01 E9 }
	$a92 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 83 C6 01 66 89 45 00 E9 }
	$a93 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 83 EE FF 66 89 45 00 E9 }
	$a94 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 ED 02 8D 76 01 66 89 45 00 E9 }
	$a95 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 83 EE FF 83 ED 02 66 89 45 00 E9 }
	$a96 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8A 04 07 8D 76 01 83 ED 02 66 89 45 00 E9 }
	$a97 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 04 07 83 ED 02 66 89 45 00 E9 }
	$a98 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 55 00 83 C5 02 66 89 14 07 E9 }
	$a99 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 8B 55 00 83 C5 02 88 14 07 E9 }
	$a100 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 66 98 98 83 ED 04 89 45 00 E9 }
	$a101 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 83 ED 02 66 89 45 00 E9 }
	$a102 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 8D 76 01 8A 04 07 83 ED 02 66 89 45 00 E9 }
	$a103 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 50 57 9C 55 52 56 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a104 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 50 9C 53 55 57 52 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 C6 02 E9 }
	$a105 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 53 9C 56 57 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a106 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 54 53 56 57 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a107 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 57 56 55 53 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a108 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 52 9C 50 53 57 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a109 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 52 55 9C 52 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a110 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 54 57 56 52 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a111 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 53 9C 52 56 55 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 EE FC E9 }
	$a112 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 55 53 56 51 57 52 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a113 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 55 9C 57 57 56 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a114 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 53 53 9C 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a115 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 53 55 57 52 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5D 9D 5A 5F 5D 5B 5E 59 58 C3 }
	$a116 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 55 52 9C 57 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9 }
	$a117 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 51 56 9C 53 57 55 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a118 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 53 9C 55 56 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a119 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 57 56 55 56 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a120 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 51 9C 56 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a121 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 53 53 55 9C 57 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a122 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 53 56 51 55 9C 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a123 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 56 53 57 51 9C 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a124 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 56 9C 53 54 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a125 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 57 56 57 9C 51 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a126 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 57 9C 54 53 55 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a127 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 9C 50 55 53 51 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a128 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 52 9C 55 53 57 51 53 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a129 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 50 9C 51 57 52 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 EE FC 83 ED 04 89 45 00 E9 }
	$a130 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 51 57 53 9C 52 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a131 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 52 51 55 55 56 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a132 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 54 52 57 51 55 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a133 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 56 52 56 51 9C 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 A7 72 45 00 C3 }
	$a134 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 56 57 52 55 51 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a135 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 51 56 57 52 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9 }
	$a136 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 52 52 9C 56 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a137 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 57 52 9C 51 56 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a138 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 52 57 51 9C 53 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a139 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 53 51 57 9C 56 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a140 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 53 56 52 57 56 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a141 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 52 53 51 52 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a142 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 53 57 51 52 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a143 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 55 9C 56 57 57 51 52 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 8D 76 02 89 45 00 E9 }
	$a144 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 51 51 9C 52 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9 }
	$a145 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 52 53 55 57 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a146 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 53 50 55 9C 51 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a147 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 53 51 55 57 52 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a148 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 52 53 51 55 9C 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9 }
	$a149 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 53 57 52 56 51 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a150 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 55 51 55 9C 56 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a151 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 52 53 57 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a152 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 53 51 55 51 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a153 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 53 55 51 56 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9 }
	$a154 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 52 56 56 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a155 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 53 56 53 52 55 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a156 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 53 57 52 57 56 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a157 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 54 55 56 52 53 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a158 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 55 52 51 56 57 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a159 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 55 54 56 52 57 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a160 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 9C 56 53 53 55 57 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a161 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 52 9C 53 57 50 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a162 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 55 56 50 53 9C 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 0F B6 06 46 83 ED 02 66 89 45 00 E9 }
	$a163 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 57 9C 53 53 55 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a164 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 9C 56 53 57 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a165 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 50 9C 56 53 57 55 52 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a166 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 9C 56 53 55 52 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a167 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 50 53 56 55 57 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a168 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 53 55 9C 55 56 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9 }
	$a169 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 55 9C 56 53 52 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 5A 58 5F 5A 5B 5E 9D 5D 59 59 C3 }
	$a170 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 57 53 55 56 50 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a171 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 53 55 50 9C 55 56 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a172 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 53 56 52 51 50 9C 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
	$a173 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 52 56 57 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a174 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 57 9C 56 50 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a175 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 9C 53 56 57 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 89 EC 5A 5B 58 5F 5E 5A 9D 5A 5D 59 C3 }
	$a176 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 53 57 50 52 50 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a177 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 57 50 9C 56 52 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a178 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 9C 52 50 57 56 53 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a179 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 52 9C 57 54 55 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9 }
	$a180 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 53 53 50 9C 52 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a181 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 56 53 55 57 9C 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a182 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 52 55 50 9C 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9 }
	$a183 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 57 55 50 52 9C 56 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a184 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 56 9C 50 55 53 54 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a185 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 50 55 56 53 9C 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a186 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 52 56 53 50 55 9C 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9 }
	$a187 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 56 52 53 55 53 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a188 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 56 52 9C 50 53 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5F 5D 5B 58 9D 5A 5E 59 59 C3 }
	$a189 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 57 9C 50 53 56 51 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a190 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 52 53 50 56 57 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a191 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 52 57 50 53 55 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9 }
	$a192 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 50 57 53 56 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a193 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 53 50 52 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a194 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 55 53 53 56 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9 }
	$a195 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 56 50 52 57 57 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
	$a196 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 50 50 56 53 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a197 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 50 55 52 56 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a198 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 57 53 50 55 51 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a199 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 53 51 9C 55 54 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a200 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 53 9C 55 51 54 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a201 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 56 9C 57 53 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a202 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 9C 51 56 51 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a203 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 55 9C 54 56 53 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a204 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 56 57 53 9C 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a205 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 50 9C 55 53 51 56 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a206 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 50 55 57 56 57 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a207 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 50 56 55 53 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a208 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 53 50 57 9C 55 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 EC 5B 5E 5D 5D 9D 5F 58 5B 59 5A C3 }
	$a209 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 55 57 53 9C 50 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a210 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 56 53 55 57 9C 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 83 EE FC 89 45 00 E9 }
	$a211 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 56 9C 56 53 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a212 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 52 50 56 57 51 9C 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9 }
	$a213 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 50 55 51 56 9C 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a214 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 50 56 53 57 9C 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 59 5D 9D 5F 5A 5E 58 5B 5A C3 }
	$a215 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 53 9C 57 55 51 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a216 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 55 50 9C 56 54 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a217 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 56 55 56 9C 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }
	$a218 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 57 55 56 51 50 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a219 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 9C 50 56 51 55 54 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a220 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 9C 50 56 51 55 57 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9 }
	$a221 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 51 50 55 53 56 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a222 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 53 57 51 55 56 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a223 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 54 56 50 9C 55 53 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a224 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 50 53 56 51 9C 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a225 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 50 57 53 56 9C 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a226 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 53 50 56 53 51 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a227 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 51 53 50 9C 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a228 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 51 9C 53 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 C6 04 83 ED 04 89 45 00 E9 }
	$a229 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 9C 57 51 50 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a230 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 9C 50 51 57 53 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a231 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 9C 55 56 57 51 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a232 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 53 50 55 9C 57 51 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a233 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 53 51 50 9C 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a234 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 55 9C 56 57 50 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a235 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 56 57 55 53 9C 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }
	$a236 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 56 9C 57 50 53 55 57 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a237 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 50 53 51 56 55 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a238 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 53 9C 50 50 56 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a239 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 53 9C 54 55 51 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a240 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 57 56 51 50 9C 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a241 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 9C 56 53 55 57 54 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a242 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 51 51 9C 52 57 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9 }
	$a243 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 51 53 52 57 55 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a244 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 54 9C 51 56 55 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a245 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 50 51 9C 52 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a246 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 52 51 9C 52 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a247 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 55 57 53 52 9C 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a248 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 53 9C 52 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a249 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 56 55 51 9C 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a250 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 56 9C 55 52 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a251 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 57 9C 56 51 52 55 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a252 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 50 56 57 51 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a253 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 54 51 57 52 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a254 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 50 9C 55 56 54 57 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a255 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 50 52 52 57 55 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a256 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 50 9C 55 52 50 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9 }
	$a257 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 52 55 56 55 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a258 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 52 55 56 56 9C 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a259 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 55 56 52 9C 57 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9 }
	$a260 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 56 50 57 55 52 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a261 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 9C 52 57 55 50 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a262 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 50 56 51 57 56 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 46 E9 }
	$a263 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 55 9C 57 56 51 50 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 EC 5A 5E 58 59 5E 5F 9D 5D 5A 5B C3 }
	$a264 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 56 9C 57 50 51 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a265 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 50 55 51 9C 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a266 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 55 51 9C 56 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a267 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 57 55 56 51 55 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a268 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 9C 55 57 50 51 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a269 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 9C 56 50 53 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a270 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 50 52 57 56 51 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a271 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 51 9C 56 50 57 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a272 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 52 57 57 50 9C 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a273 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 55 57 51 56 50 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 83 C6 04 89 45 00 E9 }
	$a274 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 9C 50 57 57 51 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a275 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 9C 56 57 51 50 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 }
	$a276 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 50 56 52 57 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a277 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 51 55 50 57 9C 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a278 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 51 9C 57 55 52 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a279 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 51 50 52 55 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a280 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 9C 52 52 51 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a281 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 51 52 50 51 9C 56 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 36 88 10 E9 }
	$a282 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 52 55 50 51 57 56 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a283 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 52 55 56 55 50 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a284 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 55 56 52 56 51 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a285 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 56 51 50 9C 52 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a286 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 57 9C 56 50 51 55 52 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a287 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 51 56 52 56 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a288 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 52 50 51 57 56 55 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a289 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 53 56 51 57 55 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a290 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 56 51 52 50 55 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a291 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 9C 57 55 53 51 52 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a292 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 51 9C 50 57 53 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9 }
	$a293 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 52 }
	$a294 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 52 51 9C 57 53 52 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a295 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 57 52 51 9C 53 56 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9 }
	$a296 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 9C 56 52 51 53 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a297 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 50 52 57 53 9C 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a298 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 50 53 53 52 57 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 6D 00 E9 }
	$a299 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 52 50 56 53 57 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a300 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 52 53 50 9C 57 56 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a301 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 53 51 56 52 9C 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a302 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 53 57 52 57 56 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a303 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 53 51 52 50 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a304 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 53 56 50 56 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a305 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 51 9C 57 56 52 50 56 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a306 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 56 53 57 51 52 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a307 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 57 50 9C 53 56 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a308 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 52 57 51 56 53 57 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a309 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 51 51 56 50 52 57 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a310 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 52 50 56 56 9C 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a311 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 53 52 9C 57 56 50 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a312 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 52 57 50 55 53 9C 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8A 06 46 83 ED 02 66 89 45 00 E9 }
	$a313 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 57 51 52 53 53 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a314 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 57 53 52 50 51 55 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a315 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 50 52 53 52 51 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a316 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 50 56 51 52 53 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a317 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 51 9C 56 53 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a318 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 52 51 9C 53 53 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a319 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 9C 51 56 53 52 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a320 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 57 9C 53 51 50 52 51 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }
	$a321 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 51 55 56 53 52 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a322 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 51 50 53 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a323 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 51 57 53 56 54 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 8D 76 04 89 45 00 E9 }
	$a324 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 52 53 50 51 51 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a325 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 53 50 54 57 51 56 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a326 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 56 50 51 53 52 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a327 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 57 51 50 52 53 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a328 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 9C 57 56 50 52 53 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a329 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 51 53 57 52 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a330 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 52 9C 52 51 57 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9 }
	$a331 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 53 9C 51 57 52 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9 }
	$a332 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 55 50 52 51 57 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a333 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 55 51 53 50 52 9C 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a334 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 57 9C 51 53 52 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a335 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 51 52 55 57 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a336 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 53 54 57 55 50 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a337 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 57 56 52 55 50 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a338 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 51 9C 57 52 50 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 }
	$a339 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 50 53 51 57 9C 57 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a340 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 55 50 57 51 53 9C 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9 }
	$a341 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 55 50 9C 51 57 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a342 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 57 53 57 55 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9 }
	$a343 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 9C 55 53 51 50 51 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a344 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 52 9C 57 51 55 55 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 }
	$a345 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 50 53 9C 57 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a346 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 52 9C 55 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a347 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 52 9C 57 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8A 06 8A 04 07 46 83 ED 02 66 89 45 00 E9 }
	$a348 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 53 9C 57 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 0F B6 06 66 98 98 46 83 ED 04 89 45 00 E9 }
	$a349 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 51 55 9C 51 50 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a350 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 52 50 9C 51 55 54 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a351 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 52 51 55 9C 50 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 0F B6 06 83 ED 02 46 66 89 45 00 E9 }
	$a352 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 55 51 9C 52 55 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9 }
	$a353 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 55 52 51 55 57 9C 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a354 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 57 52 50 51 51 9C 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a355 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 53 9C 55 50 54 51 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a356 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 50 51 57 50 52 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a357 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 51 57 54 53 9C 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a358 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 51 9C 52 50 53 57 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }
	$a359 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 52 57 50 57 51 9C 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9 }
	$a360 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 53 50 57 53 9C 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a361 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 53 9C 57 52 51 55 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9 }
	$a362 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 55 57 51 9C 50 52 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a363 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 52 53 57 51 55 50 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a364 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 55 52 9C 50 51 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a365 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 55 53 52 51 9C 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a366 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 57 9C 50 55 51 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a367 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 50 57 55 51 52 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a368 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 51 55 52 51 57 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a369 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 52 53 55 52 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a370 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 9C 53 52 50 51 55 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a371 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 52 53 56 57 9C 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9 }
	$a372 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 53 54 51 55 56 9C 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a373 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 52 55 51 53 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }
	$a374 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 55 9C 56 52 51 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8A 45 00 83 ED 02 00 45 04 9C 8F 45 00 E9 }
	$a375 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 55 9C 56 53 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9 }
	$a376 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 56 53 51 55 9C 55 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9 }
	$a377 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 50 9C 55 53 56 52 53 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 59 5B 5A 5E 58 5D 9D 58 5F C3 }
	$a378 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 50 52 54 9C 53 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a379 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 52 53 56 9C 55 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a380 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 53 55 50 55 56 52 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a381 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 53 56 55 50 9C 52 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a382 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 56 57 55 52 9C 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8A 06 83 ED 02 66 89 45 00 46 E9 }
	$a383 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 51 56 9C 56 53 55 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 06 8D 76 02 83 ED 02 66 89 45 00 E9 }
	$a384 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 50 53 51 56 55 51 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a385 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 50 9C 56 53 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a386 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 54 55 51 50 9C 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 75 00 83 C5 04 E9 }
	$a387 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 53 56 50 55 51 9C 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a388 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 56 50 9C 53 50 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a389 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 52 56 57 55 53 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }
	$a390 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 51 56 52 50 9C 50 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a391 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 52 51 57 55 9C 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 83 EE FC 83 ED 04 89 45 00 E9 }
	$a392 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 53 56 55 55 9C 50 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a393 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 54 53 9C 55 52 50 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a394 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 51 9C 55 52 53 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a395 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 52 50 56 9C 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5A 5B 59 9D 5E 58 5F 5D 5F C3 }
	$a396 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 55 9C 52 56 53 56 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 21 71 45 00 C3 }
	$a397 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 52 50 51 56 55 53 9C 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a398 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 52 53 55 55 9C 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 8B 00 89 45 00 E9 }
	$a399 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 55 54 52 51 9C 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a400 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 C6 02 83 ED 02 66 89 45 00 E9 }
	$a401 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 C6 02 98 83 ED 04 89 45 00 E9 }
	$a402 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 83 C6 02 E9 }
	$a403 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 83 EE FE E9 }
	$a404 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 66 89 45 00 8D 76 02 E9 }
	$a405 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 83 C6 02 66 89 45 00 E9 }
	$a406 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 83 EE FE 66 89 45 00 E9 }
	$a407 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 ED 02 8D 76 02 66 89 45 00 E9 }
	$a408 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 EE FE 83 ED 02 66 89 45 00 E9 }
	$a409 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 83 EE FE 98 83 ED 04 89 45 00 E9 }
	$a410 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 8D 76 02 83 ED 02 66 89 45 00 E9 }
	$a411 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 8D 76 02 98 83 ED 04 89 45 00 E9 }
	$a412 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 C6 02 83 ED 04 89 45 00 E9 }
	$a413 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 83 C6 02 89 45 00 E9 }
	$a414 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 83 EE FE 89 45 00 E9 }
	$a415 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 83 C6 02 E9 }
	$a416 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 83 EE FE E9 }
	$a417 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 89 45 00 8D 76 02 E9 }
	$a418 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 ED 04 8D 76 02 89 45 00 E9 }
	$a419 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 83 EE FE 83 ED 04 89 45 00 E9 }
	$a420 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 98 8D 76 02 83 ED 04 89 45 00 E9 }
	$a421 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 C6 02 83 ED 02 66 89 45 00 E9 }
	$a422 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 C6 02 98 83 ED 04 89 45 00 E9 }
	$a423 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 83 C6 02 E9 }
	$a424 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 83 EE FE E9 }
	$a425 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 66 89 45 00 8D 76 02 E9 }
	$a426 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 83 C6 02 66 89 45 00 E9 }
	$a427 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 83 EE FE 66 89 45 00 E9 }
	$a428 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 ED 02 8D 76 02 66 89 45 00 E9 }
	$a429 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 EE FE 83 ED 02 66 89 45 00 E9 }
	$a430 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 83 EE FE 98 83 ED 04 89 45 00 E9 }
	$a431 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 8D 76 02 83 ED 02 66 89 45 00 E9 }
	$a432 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 8D 76 02 98 83 ED 04 89 45 00 E9 }
	$a433 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 C6 02 83 ED 04 89 45 00 E9 }
	$a434 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 83 C6 02 89 45 00 E9 }
	$a435 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 83 EE FE 89 45 00 E9 }
	$a436 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 C6 02 E9 }
	$a437 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 83 EE FE E9 }
	$a438 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 89 45 00 8D 76 02 E9 }
	$a439 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 ED 04 8D 76 02 89 45 00 E9 }
	$a440 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 83 EE FE 83 ED 04 89 45 00 E9 }
	$a441 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 06 98 8D 76 02 83 ED 04 89 45 00 E9 }
	$a442 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 66 8B 55 02 F6 D0 F6 D2 83 ED 02 20 D0 66 89 45 04 9C 8F 45 00 E9 }
	$a443 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 83 ED 02 66 01 45 04 9C 8F 45 00 E9 }
	$a444 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 8A 4D 02 83 ED 02 66 D3 E0 66 89 45 04 9C 8F 45 00 E9 }
	$a445 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 8A 4D 02 83 ED 02 66 D3 E8 66 89 45 04 9C 8F 45 00 E9 }
	$a446 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 6D 00 E9 }
	$a447 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 E0 3C 8B 14 07 83 ED 04 89 55 00 E9 }
	$a448 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 E0 3C 8B 55 00 83 C5 04 89 14 07 E9 }
	$a449 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E8 83 ED 02 66 89 45 00 E9 }
	$a450 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a451 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 59 5E 5D 5B 9D 5F 5A 5E C3 }
	$a452 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5A 5D 5B 5E 59 5A 9D 5F C3 }
	$a453 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5A 5D 5B 9D 59 5F 5F 5E C3 }
	$a454 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5B 5E 5D 58 5F 9D 59 5A C3 }
	$a455 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5B 5E 5D 9D 5B 59 5A 5F C3 }
	$a456 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5E 5A 59 5D 59 9D 5F 5B C3 }
	$a457 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5F 5B 5F 5D 59 5E 9D 5A C3 }
	$a458 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 9D 5B 5D 5E 5F 5A 59 5E C3 }
	$a459 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5A 5B 5E 58 5D 5F 9D 5B C3 }
	$a460 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5A 5E 58 9D 5D 58 5B 5F C3 }
	$a461 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 58 5D 5F 9D 5A 5E 5E C3 }
	$a462 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 5E 5A 5F 58 5D 9D 58 C3 }
	$a463 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 5F 5E 58 9D 5D 5A 5E C3 }
	$a464 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 9D 5E 5F 5A 58 5D 5D C3 }
	$a465 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5D 5F 5E 5A 5B 9D 5B 58 C3 }
	$a466 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5E 58 5D 5B 9D 5F 5A 5A C3 }
	$a467 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5E 5B 5F 5B 9D 58 5D 5A C3 }
	$a468 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5F 58 5A 9D 5D 5E 5E 5B C3 }
	$a469 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 58 5B 5E 59 5D 9D 5F 59 C3 }
	$a470 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 58 5E 5D 5B 5B 9D 59 5F C3 }
	$a471 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 59 5B 5D 5A 5E 9D 5F 58 C3 }
	$a472 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 59 5F 59 58 9D 5E 5D 5B C3 }
	$a473 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5B 58 9D 5E 5F 5D 59 5F C3 }
	$a474 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5B 59 5D 5E 58 5F 9D 5D C3 }
	$a475 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5E 5D 9D 5B 58 5F 59 59 C3 }
	$a476 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5F 58 59 5B 5D 5E 9D 58 C3 }
	$a477 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5B 59 5D 5F 58 5E 5E C3 }
	$a478 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 59 5D 5D 58 5B 5F C3 }
	$a479 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 5B 5F 5B 58 5D 59 C3 }
	$a480 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 9D 5E 5D 58 5F 5B 59 58 C3 }
	$a481 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 58 9D 59 5F 5E 59 5A C3 }
	$a482 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 59 5F 5E 58 9D 5A 5E C3 }
	$a483 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5D 5E 59 5F 58 9D 58 5A C3 }
	$a484 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5E 5A 58 5F 58 59 9D 5D C3 }
	$a485 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 5F 5A 59 58 5D 9D 5E 5A C3 }
	$a486 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 58 5F 5E 59 5D 5D 5A C3 }
	$a487 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 59 5E 5D 5D 5F 5A 58 C3 }
	$a488 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 5E 5A 5E 59 5F 5D 58 C3 }
	$a489 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 58 5A 5B 5D 9D 5F 5E 59 C3 }
	$a490 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 59 9D 5D 58 5B 5E 5A 5F C3 }
	$a491 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 5B 5F 58 5E 59 5A 9D C3 }
	$a492 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 5F 58 5B 5A 5A 59 9D C3 }
	$a493 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 9D 5F 5B 5A 5B 58 59 C3 }
	$a494 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5F 5E 58 9D 59 5A 5B 5A C3 }
	$a495 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 59 5D 9D 58 5B 5A 5F 5A C3 }
	$a496 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5A 59 5D 5B 58 5F 9D 5F C3 }
	$a497 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5A 5F 58 58 5D 59 5B 9D C3 }
	$a498 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 59 5D 5F 9D 5A 58 5F C3 }
	$a499 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 5A 59 5D 58 5F 9D 5D C3 }
	$a500 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 5D 5A 5F 58 59 58 9D C3 }
	$a501 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5F 5B 59 5D 58 9D 5A 5D C3 }
	$a502 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5F 5F 9D 59 5D 5A 5B 58 C3 }
	$a503 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5A 5B 5E 5D 5B 9D 59 58 C3 }
	$a504 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5A 5E 5E 59 9D 5D 5B 58 C3 }
	$a505 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5B 5E 5B 5D 59 5A 9D 58 C3 }
	$a506 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 58 5D 5B 59 9D 5A 5D C3 }
	$a507 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 5D 59 9D 5B 58 5A 5A C3 }
	$a508 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5E 9D 5D 58 5B 5A 5A 59 C3 }
	$a509 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 9D 5B 59 5E 5B 5D 58 5A C3 }
	$a510 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 58 5F 5F 5B 5A 59 5D 5E C3 }
	$a511 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5D 59 5F 5E 58 58 5A 5B C3 }
	$a512 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5D 5E 58 59 5B 5F 5A 5F C3 }
	$a513 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5F 5D 5E 5B 58 59 5A 59 C3 }
	$a514 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5A 9D 5D 59 5B 59 5E 5F C3 }
	$a515 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 59 59 5E 5D 5F 5A 9D C3 }
	$a516 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 59 5F 5A 5E 5D 9D 5A C3 }
	$a517 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 5A 5F 59 5D 5D 5E 9D C3 }
	$a518 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5B 9D 5A 5F 5D 5A 5E 59 C3 }
	$a519 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 59 5A 59 5E 5D 5B 9D C3 }
	$a520 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 5B 5D 5E 5B 5A 59 9D C3 }
	$a521 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 5F 5E 59 5E 5D 5B 5A 9D C3 }
	$a522 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 58 9D 5F 5D 5E 5B 59 5A 5A C3 }
	$a523 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 58 5A 5F 5B 5E 5D 5D 9D C3 }
	$a524 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 58 5B 5D 5F 5E 5A 5F 9D C3 }
	$a525 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5A 9D 5E 58 5F 5D 59 5B C3 }
	$a526 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5A 9D 5F 5B 5B 5D 58 5E C3 }
	$a527 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5B 58 5A 5B 5F 5E 9D 5D C3 }
	$a528 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5D 58 59 9D 5E 5A 5B 5F C3 }
	$a529 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 5F 5B 58 59 5D 9D 5D 5E C3 }
	$a530 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 5F 5F 58 5E 5D 9D 59 5B C3 }
	$a531 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 9D 5E 5D 58 5F 5A 59 5B C3 }
	$a532 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 58 5D 5F 9D 5A 59 5F C3 }
	$a533 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 59 5A 58 9D 5D 5B 5F C3 }
	$a534 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 9D 58 5D 5F 5A 5D 59 C3 }
	$a535 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5F 58 5A 5E 9D 5D 59 59 C3 }
	$a536 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5F 5B 9D 59 5A 5D 58 5E C3 }
	$a537 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 9D 5A 5F 59 58 5D 5E 5E C3 }
	$a538 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5D 58 5F 59 5B 9D 5E 5A C3 }
	$a539 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5E 9D 58 5B 5F 59 58 5A C3 }
	$a540 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 59 59 5A 5E 5B 9D 58 C3 }
	$a541 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 5A 5E 5D 5B 58 9D 59 C3 }
	$a542 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 5E 5B 9D 58 5B 59 5A C3 }
	$a543 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 58 5A 5D 5F 5B 5A 59 9D C3 }
	$a544 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 58 5F 5D 5B 5A 59 9D 5F C3 }
	$a545 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 59 58 5F 5D 58 5B 9D 5A C3 }
	$a546 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 59 5F 5B 5D 58 5A 9D 5E C3 }
	$a547 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 59 5B 5A 58 5F 9D 58 C3 }
	$a548 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 5A 58 59 5B 5A 5F 9D C3 }
	$a549 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 5A 5F 59 58 9D 5B 5B C3 }
	$a550 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5F 9D 5D 5B 58 5E 5A 59 C3 }
	$a551 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 59 5E 5F 5D 5A 9D C3 }
	$a552 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 5F 5A 59 5D 9D 5E C3 }
	$a553 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 58 5B 9D 5A 5D 5F 5E 59 C3 }
	$a554 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5A 5B 59 5D 9D 59 5E 58 C3 }
	$a555 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5D 58 59 9D 5E 5B 5A 5E C3 }
	$a556 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5D 5E 58 5B 9D 59 5A 5B C3 }
	$a557 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5E 9D 59 5A 5A 5B 58 5D C3 }
	$a558 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5F 5F 5B 5A 9D 5E 5D 59 58 C3 }
	$a559 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 59 5A 5F 5E 5D 5D 58 5B C3 }
	$a560 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 59 5D 5B 5F 58 5E 5A 5A C3 }
	$a561 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 58 5B 5F 59 5D 5E 59 C3 }
	$a562 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 5F 58 5B 59 5B 5D 5E C3 }
	$a563 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 5F 5D 58 5B 58 59 5E C3 }
	$a564 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5B 5D 5A 5F 59 5E 58 59 C3 }
	$a565 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5D 5A 5B 58 5F 5E 5E 59 C3 }
	$a566 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5F 58 5A 5E 5D 5E 5B 59 C3 }
	$a567 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 5D 5F 5B 9D 5A 5F C3 }
	$a568 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 5F 5D 5B 5A 5A 9D C3 }
	$a569 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 59 5E 9D 5F 59 5A 5B 5D C3 }
	$a570 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5B 5D 5E 5A 5E 59 9D 5F C3 }
	$a571 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5E 5F 5D 5A 58 5B 9D 59 C3 }
	$a572 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 5F 5E 5E 5A 5D 5B 59 9D C3 }
	$a573 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 58 9D 5B 5E 5A 5D 5F 5F 59 C3 }
	$a574 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5A 5B 9D 58 5E 5F 58 5D C3 }
	$a575 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5D 5D 5A 5F 5E 58 9D 5B C3 }
	$a576 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5D 5F 5B 5E 9D 58 5A 5B C3 }
	$a577 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5F 5D 9D 5E 5B 5A 5A 58 C3 }
	$a578 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5F 5F 5E 5D 5A 5B 9D 58 C3 }
	$a579 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 59 58 5D 5E 5D 5F 5B 9D C3 }
	$a580 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 59 5F 58 5E 9D 5D 5F 5B C3 }
	$a581 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5B 5D 5E 58 5F 59 5D 9D C3 }
	$a582 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5B 5F 58 5D 5E 5D 59 9D C3 }
	$a583 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 5F 5E 58 5D 59 5D 5B 9D C3 }
	$a584 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5A 59 5E 9D 5E 5D 5F C3 }
	$a585 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5D 58 9D 59 5A 5F 5E C3 }
	$a586 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5D 5E 5F 9D 5A 59 5A C3 }
	$a587 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 59 9D 5D 5A 5E 58 5F 5F C3 }
	$a588 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5A 5F 5E 5D 58 58 59 9D C3 }
	$a589 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5A 9D 58 5F 5E 5E 59 5D C3 }
	$a590 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5D 5F 5E 9D 58 5A 59 58 C3 }
	$a591 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5E 59 5F 5D 5D 9D 58 5A C3 }
	$a592 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 9D 5F 5D 58 5A 5E 59 58 C3 }
	$a593 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 59 5E 5A 58 5B 5F 59 9D C3 }
	$a594 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5E 58 5A 9D 5F 59 5B 59 C3 }
	$a595 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5E 58 5F 5A 59 5B 5B 9D C3 }
	$a596 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5F 5A 5B 5E 58 9D 59 5F C3 }
	$a597 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5F 5B 5D 58 5E 5A 59 9D C3 }
	$a598 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 9D 5A 5B 59 58 5E 58 5F C3 }
	$a599 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5A 5F 59 5B 5D 58 5B 9D C3 }
	$a600 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5A 5F 5B 9D 58 5E 59 5D C3 }
	$a601 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5B 5A 58 5D 59 5F 9D 5F C3 }
	$a602 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5D 5B 5F 5E 59 58 9D 5A C3 }
	$a603 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5E 5A 58 5D 9D 59 5F 5B C3 }
	$a604 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5E 5B 58 9D 59 5D 5F 5A C3 }
	$a605 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5F 58 5B 5A 59 5D 9D 5D C3 }
	$a606 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 9D 5A 5D 5F 58 5B 59 5B C3 }
	$a607 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 59 59 5A 5B 9D 5E 58 5D C3 }
	$a608 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5A 59 5D 9D 5E 58 5B 5A C3 }
	$a609 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5B 9D 5D 5A 5E 58 5A 59 C3 }
	$a610 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5E 9D 5F 59 5A 5D 58 5B C3 }
	$a611 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5A 59 5E 5D 5F 5B 5A 58 C3 }
	$a612 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5E 5A 58 5F 5D 5B 59 5F C3 }
	$a613 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5E 5F 5B 5D 58 5A 59 59 C3 }
	$a614 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5A 5B 5E 5F 9D 5D 5F 59 C3 }
	$a615 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5A 5E 5F 5B 5B 5D 59 9D C3 }
	$a616 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5F 5E 59 9D 5D 5B 59 5A C3 }
	$a617 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5F 5E 5B 59 5D 5A 9D 59 C3 }
	$a618 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 59 58 5B 5E 5F 5A 9D 5D C3 }
	$a619 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5D 5A 58 9D 5B 5E 5F 58 C3 }
	$a620 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5E 5A 5F 5B 9D 5B 58 5D C3 }
	$a621 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5E 5F 5D 5A 5B 58 5A 9D C3 }
	$a622 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 59 5F 5B 58 5A 9D 58 5E 5D C3 }
	$a623 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 58 5B 59 5E 5D 5F 5F 9D C3 }
	$a624 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 59 5E 5D 5F 9D 5E 5B 58 C3 }
	$a625 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5B 5F 5E 9D 58 5D 59 5A C3 }
	$a626 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5D 59 5D 5F 58 5E 5B 9D C3 }
	$a627 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5E 5D 5B 9D 59 58 58 5F C3 }
	$a628 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5F 5D 9D 58 59 59 5B 5E C3 }
	$a629 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 9D 5B 5F 5E 5D 58 59 59 C3 }
	$a630 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 59 5D 9D 5E 5F 5A 5D 58 C3 }
	$a631 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 59 5E 5F 5D 5A 9D 58 58 C3 }
	$a632 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 5D 5E 5F 58 9D 5A 58 59 C3 }
	$a633 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 9D 58 59 58 5E 5D 5A 5F C3 }
	$a634 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 59 9D 5A 5E 58 5B 5F 58 C3 }
	$a635 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5A 5F 58 9D 5E 5B 59 58 C3 }
	$a636 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5B 58 5A 59 5F 9D 5E 58 C3 }
	$a637 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 5B 59 5F 5E 9D 5D 5A 58 C3 }
	$a638 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5D 9D 59 5F 5D 58 5E 5A 5B C3 }
	$a639 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 59 5B 59 5A 5D 9D 5F C3 }
	$a640 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 5D 5A 5A 5F 5B 9D 59 C3 }
	$a641 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 58 5F 5D 5A 59 9D 5A 5B C3 }
	$a642 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 59 58 5F 5B 5D 5D 5A 9D C3 }
	$a643 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 59 5A 5B 9D 5F 58 58 5D C3 }
	$a644 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5A 59 9D 5F 5D 5B 58 5B C3 }
	$a645 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5D 58 59 58 9D 5A 5B 5F C3 }
	$a646 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5D 5B 5A 9D 58 5A 59 5F C3 }
	$a647 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 5F 58 59 9D 5F 5B 5D 5A C3 }
	$a648 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 9D 5D 5B 59 5A 58 5F 5A C3 }
	$a649 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5E 9D 5F 5D 5B 58 5D 59 5A C3 }
	$a650 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 5A 58 5E 5D 5B 9D 59 5D C3 }
	$a651 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 5F 5B 58 59 5D 5A 5E 9D C3 }
	$a652 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 9D 58 5B 5D 5A 5A 5E 59 C3 }
	$a653 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 59 5A 5B 58 5B 5F 5E 5D C3 }
	$a654 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5D 59 58 5F 5A 5E 5B 5B C3 }
	$a655 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5D 5E 59 5B 58 5B 5F 5A C3 }
	$a656 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5F 58 5E 5A 5B 59 5D 59 C3 }
	$a657 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 5F 59 5D 5A 5B 5B 5E 58 C3 }
	$a658 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 04 07 83 ED 02 66 89 45 00 E9 }
	$a659 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 55 00 83 C5 02 66 89 14 07 E9 }
	$a660 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 8B 55 00 83 C5 02 88 14 07 E9 }
	$a661 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 66 98 98 83 ED 04 89 45 00 E9 }
	$a662 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 83 ED 02 66 89 45 00 E9 }
	$a663 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 46 8A 04 07 83 ED 02 66 89 45 00 E9 }
	$a664 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 46 83 ED 02 66 89 45 00 E9 }
	$a665 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 C6 01 83 ED 02 66 89 45 00 E9 }
	$a666 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 46 66 89 45 00 E9 }
	$a667 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 46 E9 }
	$a668 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 83 C6 01 E9 }
	$a669 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 83 EE FF E9 }
	$a670 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 66 89 45 00 8D 76 01 E9 }
	$a671 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 83 C6 01 66 89 45 00 E9 }
	$a672 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 83 EE FF 66 89 45 00 E9 }
	$a673 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 ED 02 8D 76 01 66 89 45 00 E9 }
	$a674 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 83 EE FF 83 ED 02 66 89 45 00 E9 }
	$a675 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 04 07 8D 76 01 83 ED 02 66 89 45 00 E9 }
	$a676 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 46 83 C5 02 66 89 14 07 E9 }
	$a677 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 46 83 C5 02 88 14 07 E9 }
	$a678 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 46 66 89 14 07 E9 }
	$a679 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 46 88 14 07 E9 }
	$a680 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 46 E9 }
	$a681 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 83 C6 01 E9 }
	$a682 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 83 EE FF E9 }
	$a683 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 66 89 14 07 8D 76 01 E9 }
	$a684 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 C6 01 66 89 14 07 E9 }
	$a685 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 C6 01 88 14 07 E9 }
	$a686 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 EE FF 66 89 14 07 E9 }
	$a687 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 83 EE FF 88 14 07 E9 }
	$a688 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 46 E9 }
	$a689 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 83 C6 01 E9 }
	$a690 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 83 EE FF E9 }
	$a691 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 88 14 07 8D 76 01 E9 }
	$a692 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 8D 76 01 66 89 14 07 E9 }
	$a693 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C5 02 8D 76 01 88 14 07 E9 }
	$a694 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C6 01 83 C5 02 66 89 14 07 E9 }
	$a695 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 C6 01 83 C5 02 88 14 07 E9 }
	$a696 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 EE FF 83 C5 02 66 89 14 07 E9 }
	$a697 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 83 EE FF 83 C5 02 88 14 07 E9 }
	$a698 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 8D 76 01 83 C5 02 66 89 14 07 E9 }
	$a699 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 8B 55 00 8D 76 01 83 C5 02 88 14 07 E9 }
	$a700 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 46 98 83 ED 04 89 45 00 E9 }
	$a701 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 83 C6 01 98 83 ED 04 89 45 00 E9 }
	$a702 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 83 EE FF 98 83 ED 04 89 45 00 E9 }
	$a703 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 8D 76 01 98 83 ED 04 89 45 00 E9 }
	$a704 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 46 83 ED 04 89 45 00 E9 }
	$a705 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 C6 01 83 ED 04 89 45 00 E9 }
	$a706 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 46 89 45 00 E9 }
	$a707 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 83 C6 01 89 45 00 E9 }
	$a708 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 83 EE FF 89 45 00 E9 }
	$a709 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 46 E9 }
	$a710 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 83 C6 01 E9 }
	$a711 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 83 EE FF E9 }
	$a712 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 89 45 00 8D 76 01 E9 }
	$a713 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 ED 04 8D 76 01 89 45 00 E9 }
	$a714 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 83 EE FF 83 ED 04 89 45 00 E9 }
	$a715 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 66 98 98 8D 76 01 83 ED 04 89 45 00 E9 }
	$a716 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 04 07 83 ED 02 66 89 45 00 E9 }
	$a717 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 55 00 83 C5 02 66 89 14 07 E9 }
	$a718 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 8B 55 00 83 C5 02 88 14 07 E9 }
	$a719 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 66 98 98 83 ED 04 89 45 00 E9 }
	$a720 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 83 ED 02 66 89 45 00 E9 }
	$a721 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 C6 01 8A 04 07 83 ED 02 66 89 45 00 E9 }
	$a722 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 46 66 89 45 00 E9 }
	$a723 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 46 E9 }
	$a724 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 83 C6 01 E9 }
	$a725 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 83 EE FF E9 }
	$a726 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 66 89 45 00 8D 76 01 E9 }
	$a727 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 83 C6 01 66 89 45 00 E9 }
	$a728 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 83 EE FF 66 89 45 00 E9 }
	$a729 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 ED 02 8D 76 01 66 89 45 00 E9 }
	$a730 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 04 07 83 ED 02 66 89 45 00 E9 }
	$a731 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 55 00 83 C5 02 66 89 14 07 E9 }
	$a732 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 8B 55 00 83 C5 02 88 14 07 E9 }
	$a733 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 66 98 98 83 ED 04 89 45 00 E9 }
	$a734 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 83 ED 02 66 89 45 00 E9 }
	$a735 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 83 EE FF 8A 04 07 83 ED 02 66 89 45 00 E9 }
	$a736 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 46 83 ED 02 66 89 45 00 E9 }
	$a737 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 C6 01 83 ED 02 66 89 45 00 E9 }
	$a738 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 46 66 89 45 00 E9 }
	$a739 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 46 E9 }
	$a740 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 83 C6 01 E9 }
	$a741 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 83 EE FF E9 }
	$a742 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 66 89 45 00 8D 76 01 E9 }
	$a743 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 83 C6 01 66 89 45 00 E9 }
	$a744 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 83 EE FF 66 89 45 00 E9 }
	$a745 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 ED 02 8D 76 01 66 89 45 00 E9 }
	$a746 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 83 EE FF 83 ED 02 66 89 45 00 E9 }
	$a747 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8A 04 07 8D 76 01 83 ED 02 66 89 45 00 E9 }
	$a748 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 04 07 83 ED 02 66 89 45 00 E9 }
	$a749 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 55 00 83 C5 02 66 89 14 07 E9 }
	$a750 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 55 00 83 C5 02 88 14 07 E9 }
	$a751 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 98 98 83 ED 04 89 45 00 E9 }
	$a752 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 83 ED 02 66 89 45 00 E9 }
	$a753 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 8A 04 07 83 ED 02 66 89 45 00 E9 }
	$a754 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 83 ED 02 00 45 04 9C 8F 45 00 E9 }
	$a755 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 8A 4D 02 83 ED 02 D2 E0 66 89 45 04 9C 8F 45 00 E9 }
	$a756 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 45 00 8A 4D 02 83 ED 02 D2 E8 66 89 45 04 9C 8F 45 00 E9 }
	$a757 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 C6 04 83 ED 04 89 45 00 E9 }
	$a758 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 83 C6 04 89 45 00 E9 }
	$a759 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 83 EE FC 89 45 00 E9 }
	$a760 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 C6 04 E9 }
	$a761 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 83 EE FC E9 }
	$a762 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 8D 76 04 E9 }
	$a763 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 8D 76 04 89 45 00 E9 }
	$a764 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 EE FC 83 ED 04 89 45 00 E9 }
	$a765 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9 }
	$a766 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a767 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 36 8B 00 89 45 00 E9 }
	$a768 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 36 89 10 E9 }
	$a769 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
	$a770 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 36 8B 00 66 89 45 00 E9 }
	$a771 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 }
	$a772 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E0 89 45 04 9C 8F 45 00 E9 }
	$a773 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E8 89 45 04 9C 8F 45 00 E9 }
	$a774 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 4D 04 83 ED 02 D3 E8 89 45 04 9C 8F 45 00 E9 01 7D 00 00 }
	$a775 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 36 88 10 E9 }
	$a776 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a777 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a778 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 36 89 10 E9 }
	$a779 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }
	$a780 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 8A 4D 08 83 C5 02 0F A5 D0 89 45 04 9C 8F 45 00 E9 }
	$a781 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 8A 4D 08 83 C5 02 0F AD D0 89 45 04 9C 8F 45 00 E9 }
	$a782 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 F7 D0 F7 D2 21 D0 89 45 04 9C 8F 45 00 E9 }
	$a783 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 83 C5 02 36 8A 02 66 89 45 00 E9 }
	$a784 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9 }
	$a785 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 6D 00 E9 }
	$a786 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }
	$a787 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 47 50 39 C5 0F 87 ?? ?? ?? ?? 8D 4F 40 29 E1 8D 45 80 29 C8 89 C4 9C 56 89 FE 8D BD 40 FF FF FF 57 FC F3 A4 5F 5E 9D E9 }
	$a788 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 51 53 57 56 52 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 66 8B 6D 00 E9 }
	$a789 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 52 53 52 56 57 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a790 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 56 57 51 52 53 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 8A 02 66 89 45 00 E9 }
	$a791 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 56 57 53 55 51 52 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a792 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 50 57 53 51 52 55 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 58 5E 59 5D 5A 59 5B 5F 58 9D C3 }
	$a793 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 52 56 50 53 56 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8B 06 83 ED 04 8D 76 04 89 45 00 E9 }
	$a794 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 53 50 52 56 55 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a795 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 55 57 53 56 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a796 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 56 53 52 50 55 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 55 00 83 C5 02 36 8A 02 66 89 45 00 E9 }
	$a797 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 51 56 55 52 50 55 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }
	$a798 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 51 56 57 50 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }
	$a799 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 53 51 55 57 56 50 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a800 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 55 51 53 53 57 50 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a801 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 56 51 57 53 50 55 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a802 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 56 53 55 53 51 50 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }
	$a803 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 50 52 51 55 56 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a804 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 50 55 56 51 57 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a805 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 51 52 55 52 50 56 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 34 85 ?? ?? ?? ?? C3 }
	$a806 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 55 56 56 57 51 50 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a807 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 56 56 50 55 51 57 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 }
	$a808 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 53 57 50 55 56 57 51 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a809 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 50 52 56 51 50 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 59 5F 5B 5A 59 5E 5A 58 5D 9D C3 }
	$a810 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 52 56 53 57 51 54 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 01 45 04 9C 8F 45 00 E9 }
	$a811 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 56 53 57 52 51 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 8A 06 46 83 ED 02 66 89 45 00 E9 }
	$a812 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 55 57 53 52 55 51 56 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a813 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 50 52 51 57 53 55 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 83 C6 04 89 45 00 E9 }
	$a814 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 51 52 55 51 50 57 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 34 85 ?? ?? ?? ?? C3 }
	$a815 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 51 53 55 51 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a816 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 52 53 56 50 57 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 34 85 ?? ?? ?? ?? C3 }
	$a817 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 51 55 52 50 52 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }
	$a818 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 55 51 57 52 52 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 00 89 45 00 E9 }
	$a819 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 53 57 52 51 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }
	$a820 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 57 51 50 55 51 53 52 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 8B 6D 00 E9 }
	$a821 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 56 57 55 52 50 53 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 E8 83 ED 04 89 45 00 E9 }
	$a822 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 51 53 55 56 50 52 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 8D 76 04 E9 }
	$a823 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 52 53 51 55 50 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 80 E0 3C 8B 14 07 83 ED 04 89 55 00 E9 }
	$a824 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 52 55 56 51 50 53 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 34 85 ?? ?? ?? ?? C3 }
	$a825 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 57 55 52 54 50 51 53 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 04 89 45 00 E9 }
	$a826 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 }
	$a827 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F7 55 00 66 8B 45 00 83 ED 02 66 21 45 04 9C 8F 45 00 E9 }
	$a828 = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint or $a4 at entrypoint or $a5 at entrypoint or $a6 at entrypoint or $a7 at entrypoint or $a8 at entrypoint or $a9 at entrypoint or $a10 at entrypoint or $a11 at entrypoint or $a12 at entrypoint or $a13 at entrypoint or $a14 at entrypoint or $a15 at entrypoint or $a16 at entrypoint or $a17 at entrypoint or $a18 at entrypoint or $a19 at entrypoint or $a20 at entrypoint or $a21 at entrypoint or $a22 at entrypoint or $a23 at entrypoint or $a24 at entrypoint or $a25 at entrypoint or $a26 at entrypoint or $a27 at entrypoint or $a28 at entrypoint or $a29 at entrypoint or $a30 at entrypoint or $a31 at entrypoint or $a32 at entrypoint or $a33 at entrypoint or $a34 at entrypoint or $a35 at entrypoint or $a36 at entrypoint or $a37 at entrypoint or $a38 at entrypoint or $a39 at entrypoint or $a40 at entrypoint or $a41 at entrypoint or $a42 at entrypoint or $a43 at entrypoint or $a44 at entrypoint or $a45 at entrypoint or $a46 at entrypoint or $a47 at entrypoint or $a48 at entrypoint or $a49 at entrypoint or $a50 at entrypoint or $a51 at entrypoint or $a52 at entrypoint or $a53 at entrypoint or $a54 at entrypoint or $a55 at entrypoint or $a56 at entrypoint or $a57 at entrypoint or $a58 at entrypoint or $a59 at entrypoint or $a60 at entrypoint or $a61 at entrypoint or $a62 at entrypoint or $a63 at entrypoint or $a64 at entrypoint or $a65 at entrypoint or $a66 at entrypoint or $a67 at entrypoint or $a68 at entrypoint or $a69 at entrypoint or $a70 at entrypoint or $a71 at entrypoint or $a72 at entrypoint or $a73 at entrypoint or $a74 at entrypoint or $a75 at entrypoint or $a76 at entrypoint or $a77 at entrypoint or $a78 at entrypoint or $a79 at entrypoint or $a80 at entrypoint or $a81 at entrypoint or $a82 at entrypoint or $a83 at entrypoint or $a84 at entrypoint or $a85 at entrypoint or $a86 at entrypoint or $a87 at entrypoint or $a88 at entrypoint or $a89 at entrypoint or $a90 at entrypoint or $a91 at entrypoint or $a92 at entrypoint or $a93 at entrypoint or $a94 at entrypoint or $a95 at entrypoint or $a96 at entrypoint or $a97 at entrypoint or $a98 at entrypoint or $a99 at entrypoint or $a100 at entrypoint or $a101 at entrypoint or $a102 at entrypoint or $a103 at entrypoint or $a104 at entrypoint or $a105 at entrypoint or $a106 at entrypoint or $a107 at entrypoint or $a108 at entrypoint or $a109 at entrypoint or $a110 at entrypoint or $a111 at entrypoint or $a112 at entrypoint or $a113 at entrypoint or $a114 at entrypoint or $a115 at entrypoint or $a116 at entrypoint or $a117 at entrypoint or $a118 at entrypoint or $a119 at entrypoint or $a120 at entrypoint or $a121 at entrypoint or $a122 at entrypoint or $a123 at entrypoint or $a124 at entrypoint or $a125 at entrypoint or $a126 at entrypoint or $a127 at entrypoint or $a128 at entrypoint or $a129 at entrypoint or $a130 at entrypoint or $a131 at entrypoint or $a132 at entrypoint or $a133 at entrypoint or $a134 at entrypoint or $a135 at entrypoint or $a136 at entrypoint or $a137 at entrypoint or $a138 at entrypoint or $a139 at entrypoint or $a140 at entrypoint or $a141 at entrypoint or $a142 at entrypoint or $a143 at entrypoint or $a144 at entrypoint or $a145 at entrypoint or $a146 at entrypoint or $a147 at entrypoint or $a148 at entrypoint or $a149 at entrypoint or $a150 at entrypoint or $a151 at entrypoint or $a152 at entrypoint or $a153 at entrypoint or $a154 at entrypoint or $a155 at entrypoint or $a156 at entrypoint or $a157 at entrypoint or $a158 at entrypoint or $a159 at entrypoint or $a160 at entrypoint or $a161 at entrypoint or $a162 at entrypoint or $a163 at entrypoint or $a164 at entrypoint or $a165 at entrypoint or $a166 at entrypoint or $a167 at entrypoint or $a168 at entrypoint or $a169 at entrypoint or $a170 at entrypoint or $a171 at entrypoint or $a172 at entrypoint or $a173 at entrypoint or $a174 at entrypoint or $a175 at entrypoint or $a176 at entrypoint or $a177 at entrypoint or $a178 at entrypoint or $a179 at entrypoint or $a180 at entrypoint or $a181 at entrypoint or $a182 at entrypoint or $a183 at entrypoint or $a184 at entrypoint or $a185 at entrypoint or $a186 at entrypoint or $a187 at entrypoint or $a188 at entrypoint or $a189 at entrypoint or $a190 at entrypoint or $a191 at entrypoint or $a192 at entrypoint or $a193 at entrypoint or $a194 at entrypoint or $a195 at entrypoint or $a196 at entrypoint or $a197 at entrypoint or $a198 at entrypoint or $a199 at entrypoint or $a200 at entrypoint or $a201 at entrypoint or $a202 at entrypoint or $a203 at entrypoint or $a204 at entrypoint or $a205 at entrypoint or $a206 at entrypoint or $a207 at entrypoint or $a208 at entrypoint or $a209 at entrypoint or $a210 at entrypoint or $a211 at entrypoint or $a212 at entrypoint or $a213 at entrypoint or $a214 at entrypoint or $a215 at entrypoint or $a216 at entrypoint or $a217 at entrypoint or $a218 at entrypoint or $a219 at entrypoint or $a220 at entrypoint or $a221 at entrypoint or $a222 at entrypoint or $a223 at entrypoint or $a224 at entrypoint or $a225 at entrypoint or $a226 at entrypoint or $a227 at entrypoint or $a228 at entrypoint or $a229 at entrypoint or $a230 at entrypoint or $a231 at entrypoint or $a232 at entrypoint or $a233 at entrypoint or $a234 at entrypoint or $a235 at entrypoint or $a236 at entrypoint or $a237 at entrypoint or $a238 at entrypoint or $a239 at entrypoint or $a240 at entrypoint or $a241 at entrypoint or $a242 at entrypoint or $a243 at entrypoint or $a244 at entrypoint or $a245 at entrypoint or $a246 at entrypoint or $a247 at entrypoint or $a248 at entrypoint or $a249 at entrypoint or $a250 at entrypoint or $a251 at entrypoint or $a252 at entrypoint or $a253 at entrypoint or $a254 at entrypoint or $a255 at entrypoint or $a256 at entrypoint or $a257 at entrypoint or $a258 at entrypoint or $a259 at entrypoint or $a260 at entrypoint or $a261 at entrypoint or $a262 at entrypoint or $a263 at entrypoint or $a264 at entrypoint or $a265 at entrypoint or $a266 at entrypoint or $a267 at entrypoint or $a268 at entrypoint or $a269 at entrypoint or $a270 at entrypoint or $a271 at entrypoint or $a272 at entrypoint or $a273 at entrypoint or $a274 at entrypoint or $a275 at entrypoint or $a276 at entrypoint or $a277 at entrypoint or $a278 at entrypoint or $a279 at entrypoint or $a280 at entrypoint or $a281 at entrypoint or $a282 at entrypoint or $a283 at entrypoint or $a284 at entrypoint or $a285 at entrypoint or $a286 at entrypoint or $a287 at entrypoint or $a288 at entrypoint or $a289 at entrypoint or $a290 at entrypoint or $a291 at entrypoint or $a292 at entrypoint or $a293 at entrypoint or $a294 at entrypoint or $a295 at entrypoint or $a296 at entrypoint or $a297 at entrypoint or $a298 at entrypoint or $a299 at entrypoint or $a300 at entrypoint or $a301 at entrypoint or $a302 at entrypoint or $a303 at entrypoint or $a304 at entrypoint or $a305 at entrypoint or $a306 at entrypoint or $a307 at entrypoint or $a308 at entrypoint or $a309 at entrypoint or $a310 at entrypoint or $a311 at entrypoint or $a312 at entrypoint or $a313 at entrypoint or $a314 at entrypoint or $a315 at entrypoint or $a316 at entrypoint or $a317 at entrypoint or $a318 at entrypoint or $a319 at entrypoint or $a320 at entrypoint or $a321 at entrypoint or $a322 at entrypoint or $a323 at entrypoint or $a324 at entrypoint or $a325 at entrypoint or $a326 at entrypoint or $a327 at entrypoint or $a328 at entrypoint or $a329 at entrypoint or $a330 at entrypoint or $a331 at entrypoint or $a332 at entrypoint or $a333 at entrypoint or $a334 at entrypoint or $a335 at entrypoint or $a336 at entrypoint or $a337 at entrypoint or $a338 at entrypoint or $a339 at entrypoint or $a340 at entrypoint or $a341 at entrypoint or $a342 at entrypoint or $a343 at entrypoint or $a344 at entrypoint or $a345 at entrypoint or $a346 at entrypoint or $a347 at entrypoint or $a348 at entrypoint or $a349 at entrypoint or $a350 at entrypoint or $a351 at entrypoint or $a352 at entrypoint or $a353 at entrypoint or $a354 at entrypoint or $a355 at entrypoint or $a356 at entrypoint or $a357 at entrypoint or $a358 at entrypoint or $a359 at entrypoint or $a360 at entrypoint or $a361 at entrypoint or $a362 at entrypoint or $a363 at entrypoint or $a364 at entrypoint or $a365 at entrypoint or $a366 at entrypoint or $a367 at entrypoint or $a368 at entrypoint or $a369 at entrypoint or $a370 at entrypoint or $a371 at entrypoint or $a372 at entrypoint or $a373 at entrypoint or $a374 at entrypoint or $a375 at entrypoint or $a376 at entrypoint or $a377 at entrypoint or $a378 at entrypoint or $a379 at entrypoint or $a380 at entrypoint or $a381 at entrypoint or $a382 at entrypoint or $a383 at entrypoint or $a384 at entrypoint or $a385 at entrypoint or $a386 at entrypoint or $a387 at entrypoint or $a388 at entrypoint or $a389 at entrypoint or $a390 at entrypoint or $a391 at entrypoint or $a392 at entrypoint or $a393 at entrypoint or $a394 at entrypoint or $a395 at entrypoint or $a396 at entrypoint or $a397 at entrypoint or $a398 at entrypoint or $a399 at entrypoint or $a400 at entrypoint or $a401 at entrypoint or $a402 at entrypoint or $a403 at entrypoint or $a404 at entrypoint or $a405 at entrypoint or $a406 at entrypoint or $a407 at entrypoint or $a408 at entrypoint or $a409 at entrypoint or $a410 at entrypoint or $a411 at entrypoint or $a412 at entrypoint or $a413 at entrypoint or $a414 at entrypoint or $a415 at entrypoint or $a416 at entrypoint or $a417 at entrypoint or $a418 at entrypoint or $a419 at entrypoint or $a420 at entrypoint or $a421 at entrypoint or $a422 at entrypoint or $a423 at entrypoint or $a424 at entrypoint or $a425 at entrypoint or $a426 at entrypoint or $a427 at entrypoint or $a428 at entrypoint or $a429 at entrypoint or $a430 at entrypoint or $a431 at entrypoint or $a432 at entrypoint or $a433 at entrypoint or $a434 at entrypoint or $a435 at entrypoint or $a436 at entrypoint or $a437 at entrypoint or $a438 at entrypoint or $a439 at entrypoint or $a440 at entrypoint or $a441 at entrypoint or $a442 at entrypoint or $a443 at entrypoint or $a444 at entrypoint or $a445 at entrypoint or $a446 at entrypoint or $a447 at entrypoint or $a448 at entrypoint or $a449 at entrypoint or $a450 at entrypoint or $a451 at entrypoint or $a452 at entrypoint or $a453 at entrypoint or $a454 at entrypoint or $a455 at entrypoint or $a456 at entrypoint or $a457 at entrypoint or $a458 at entrypoint or $a459 at entrypoint or $a460 at entrypoint or $a461 at entrypoint or $a462 at entrypoint or $a463 at entrypoint or $a464 at entrypoint or $a465 at entrypoint or $a466 at entrypoint or $a467 at entrypoint or $a468 at entrypoint or $a469 at entrypoint or $a470 at entrypoint or $a471 at entrypoint or $a472 at entrypoint or $a473 at entrypoint or $a474 at entrypoint or $a475 at entrypoint or $a476 at entrypoint or $a477 at entrypoint or $a478 at entrypoint or $a479 at entrypoint or $a480 at entrypoint or $a481 at entrypoint or $a482 at entrypoint or $a483 at entrypoint or $a484 at entrypoint or $a485 at entrypoint or $a486 at entrypoint or $a487 at entrypoint or $a488 at entrypoint or $a489 at entrypoint or $a490 at entrypoint or $a491 at entrypoint or $a492 at entrypoint or $a493 at entrypoint or $a494 at entrypoint or $a495 at entrypoint or $a496 at entrypoint or $a497 at entrypoint or $a498 at entrypoint or $a499 at entrypoint or $a500 at entrypoint or $a501 at entrypoint or $a502 at entrypoint or $a503 at entrypoint or $a504 at entrypoint or $a505 at entrypoint or $a506 at entrypoint or $a507 at entrypoint or $a508 at entrypoint or $a509 at entrypoint or $a510 at entrypoint or $a511 at entrypoint or $a512 at entrypoint or $a513 at entrypoint or $a514 at entrypoint or $a515 at entrypoint or $a516 at entrypoint or $a517 at entrypoint or $a518 at entrypoint or $a519 at entrypoint or $a520 at entrypoint or $a521 at entrypoint or $a522 at entrypoint or $a523 at entrypoint or $a524 at entrypoint or $a525 at entrypoint or $a526 at entrypoint or $a527 at entrypoint or $a528 at entrypoint or $a529 at entrypoint or $a530 at entrypoint or $a531 at entrypoint or $a532 at entrypoint or $a533 at entrypoint or $a534 at entrypoint or $a535 at entrypoint or $a536 at entrypoint or $a537 at entrypoint or $a538 at entrypoint or $a539 at entrypoint or $a540 at entrypoint or $a541 at entrypoint or $a542 at entrypoint or $a543 at entrypoint or $a544 at entrypoint or $a545 at entrypoint or $a546 at entrypoint or $a547 at entrypoint or $a548 at entrypoint or $a549 at entrypoint or $a550 at entrypoint or $a551 at entrypoint or $a552 at entrypoint or $a553 at entrypoint or $a554 at entrypoint or $a555 at entrypoint or $a556 at entrypoint or $a557 at entrypoint or $a558 at entrypoint or $a559 at entrypoint or $a560 at entrypoint or $a561 at entrypoint or $a562 at entrypoint or $a563 at entrypoint or $a564 at entrypoint or $a565 at entrypoint or $a566 at entrypoint or $a567 at entrypoint or $a568 at entrypoint or $a569 at entrypoint or $a570 at entrypoint or $a571 at entrypoint or $a572 at entrypoint or $a573 at entrypoint or $a574 at entrypoint or $a575 at entrypoint or $a576 at entrypoint or $a577 at entrypoint or $a578 at entrypoint or $a579 at entrypoint or $a580 at entrypoint or $a581 at entrypoint or $a582 at entrypoint or $a583 at entrypoint or $a584 at entrypoint or $a585 at entrypoint or $a586 at entrypoint or $a587 at entrypoint or $a588 at entrypoint or $a589 at entrypoint or $a590 at entrypoint or $a591 at entrypoint or $a592 at entrypoint or $a593 at entrypoint or $a594 at entrypoint or $a595 at entrypoint or $a596 at entrypoint or $a597 at entrypoint or $a598 at entrypoint or $a599 at entrypoint or $a600 at entrypoint or $a601 at entrypoint or $a602 at entrypoint or $a603 at entrypoint or $a604 at entrypoint or $a605 at entrypoint or $a606 at entrypoint or $a607 at entrypoint or $a608 at entrypoint or $a609 at entrypoint or $a610 at entrypoint or $a611 at entrypoint or $a612 at entrypoint or $a613 at entrypoint or $a614 at entrypoint or $a615 at entrypoint or $a616 at entrypoint or $a617 at entrypoint or $a618 at entrypoint or $a619 at entrypoint or $a620 at entrypoint or $a621 at entrypoint or $a622 at entrypoint or $a623 at entrypoint or $a624 at entrypoint or $a625 at entrypoint or $a626 at entrypoint or $a627 at entrypoint or $a628 at entrypoint or $a629 at entrypoint or $a630 at entrypoint or $a631 at entrypoint or $a632 at entrypoint or $a633 at entrypoint or $a634 at entrypoint or $a635 at entrypoint or $a636 at entrypoint or $a637 at entrypoint or $a638 at entrypoint or $a639 at entrypoint or $a640 at entrypoint or $a641 at entrypoint or $a642 at entrypoint or $a643 at entrypoint or $a644 at entrypoint or $a645 at entrypoint or $a646 at entrypoint or $a647 at entrypoint or $a648 at entrypoint or $a649 at entrypoint or $a650 at entrypoint or $a651 at entrypoint or $a652 at entrypoint or $a653 at entrypoint or $a654 at entrypoint or $a655 at entrypoint or $a656 at entrypoint or $a657 at entrypoint or $a658 at entrypoint or $a659 at entrypoint or $a660 at entrypoint or $a661 at entrypoint or $a662 at entrypoint or $a663 at entrypoint or $a664 at entrypoint or $a665 at entrypoint or $a666 at entrypoint or $a667 at entrypoint or $a668 at entrypoint or $a669 at entrypoint or $a670 at entrypoint or $a671 at entrypoint or $a672 at entrypoint or $a673 at entrypoint or $a674 at entrypoint or $a675 at entrypoint or $a676 at entrypoint or $a677 at entrypoint or $a678 at entrypoint or $a679 at entrypoint or $a680 at entrypoint or $a681 at entrypoint or $a682 at entrypoint or $a683 at entrypoint or $a684 at entrypoint or $a685 at entrypoint or $a686 at entrypoint or $a687 at entrypoint or $a688 at entrypoint or $a689 at entrypoint or $a690 at entrypoint or $a691 at entrypoint or $a692 at entrypoint or $a693 at entrypoint or $a694 at entrypoint or $a695 at entrypoint or $a696 at entrypoint or $a697 at entrypoint or $a698 at entrypoint or $a699 at entrypoint or $a700 at entrypoint or $a701 at entrypoint or $a702 at entrypoint or $a703 at entrypoint or $a704 at entrypoint or $a705 at entrypoint or $a706 at entrypoint or $a707 at entrypoint or $a708 at entrypoint or $a709 at entrypoint or $a710 at entrypoint or $a711 at entrypoint or $a712 at entrypoint or $a713 at entrypoint or $a714 at entrypoint or $a715 at entrypoint or $a716 at entrypoint or $a717 at entrypoint or $a718 at entrypoint or $a719 at entrypoint or $a720 at entrypoint or $a721 at entrypoint or $a722 at entrypoint or $a723 at entrypoint or $a724 at entrypoint or $a725 at entrypoint or $a726 at entrypoint or $a727 at entrypoint or $a728 at entrypoint or $a729 at entrypoint or $a730 at entrypoint or $a731 at entrypoint or $a732 at entrypoint or $a733 at entrypoint or $a734 at entrypoint or $a735 at entrypoint or $a736 at entrypoint or $a737 at entrypoint or $a738 at entrypoint or $a739 at entrypoint or $a740 at entrypoint or $a741 at entrypoint or $a742 at entrypoint or $a743 at entrypoint or $a744 at entrypoint or $a745 at entrypoint or $a746 at entrypoint or $a747 at entrypoint or $a748 at entrypoint or $a749 at entrypoint or $a750 at entrypoint or $a751 at entrypoint or $a752 at entrypoint or $a753 at entrypoint or $a754 at entrypoint or $a755 at entrypoint or $a756 at entrypoint or $a757 at entrypoint or $a758 at entrypoint or $a759 at entrypoint or $a760 at entrypoint or $a761 at entrypoint or $a762 at entrypoint or $a763 at entrypoint or $a764 at entrypoint or $a765 at entrypoint or $a766 at entrypoint or $a767 at entrypoint or $a768 at entrypoint or $a769 at entrypoint or $a770 at entrypoint or $a771 at entrypoint or $a772 at entrypoint or $a773 at entrypoint or $a774 at entrypoint or $a775 at entrypoint or $a776 at entrypoint or $a777 at entrypoint or $a778 at entrypoint or $a779 at entrypoint or $a780 at entrypoint or $a781 at entrypoint or $a782 at entrypoint or $a783 at entrypoint or $a784 at entrypoint or $a785 at entrypoint or $a786 at entrypoint or $a787 at entrypoint or $a788 at entrypoint or $a789 at entrypoint or $a790 at entrypoint or $a791 at entrypoint or $a792 at entrypoint or $a793 at entrypoint or $a794 at entrypoint or $a795 at entrypoint or $a796 at entrypoint or $a797 at entrypoint or $a798 at entrypoint or $a799 at entrypoint or $a800 at entrypoint or $a801 at entrypoint or $a802 at entrypoint or $a803 at entrypoint or $a804 at entrypoint or $a805 at entrypoint or $a806 at entrypoint or $a807 at entrypoint or $a808 at entrypoint or $a809 at entrypoint or $a810 at entrypoint or $a811 at entrypoint or $a812 at entrypoint or $a813 at entrypoint or $a814 at entrypoint or $a815 at entrypoint or $a816 at entrypoint or $a817 at entrypoint or $a818 at entrypoint or $a819 at entrypoint or $a820 at entrypoint or $a821 at entrypoint or $a822 at entrypoint or $a823 at entrypoint or $a824 at entrypoint or $a825 at entrypoint or $a826 at entrypoint or $a827 at entrypoint or $a828
}
	
	
rule ThemidaWinLicenseV1820OreansTechnologiesSignbyfly
{
strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }

condition:
		$a0 at entrypoint
}
	
	
rule TTPpack
{
strings:
		$a0 = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 F6 E8 11 00 00 00 8B 64 24 08 64 8F 05 }

condition:
		$a0 at entrypoint
}
	
	
rule tElockv060
{
strings:
		$a0 = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner01BorlandDelphi30Anorganix
{
strings:
		$a0 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule PEBundlev244
{
strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }

condition:
		$a0 at entrypoint
}
	
	
rule ObsidiumV1258V133XObsidiumSoftwareSignbyfly
{
strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 EB 02 ?? ?? EB }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv120v1201
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }

condition:
		$a0 at entrypoint
}
	
	
rule Stranik13ModulaCPascal
{
strings:
		$a0 = { E8 ?? ?? FF FF E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv102a
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }

condition:
		$a0 at entrypoint
}
	
	
rule ASPackv102b
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
	$a1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule MESSv120
{
strings:
		$a0 = { FA B9 ?? ?? F3 ?? ?? E3 ?? EB ?? EB ?? B6 }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptorv13v14Vaska
{
strings:
		$a0 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }
	$a1 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PseudoSigner01PEIntro10Anorganix
{
strings:
		$a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9 }

condition:
		$a0 at entrypoint
}
	
	
rule HyingsPEArmor075exeHying
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }

condition:
		$a0
}
	
	
rule yodasProtectorV1032AshkbizDanehkarSignbyfly
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 BF A4 42 00 81 E9 8E 74 42 00 8B D5 81 C2 8E 74 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 63 29 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor120BetaPEPacker
{
strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 EB ?? 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }

condition:
		$a0 at entrypoint
}
	
	
rule Packanoid10ackanoid
{
strings:
		$a0 = { BF 00 ?? 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 ?? ?? ?? 00 8B 30 8B 78 04 BB ?? ?? ?? 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 5E EB DB B9 ?? ?? 00 00 BE 00 ?? ?? 00 EB 01 00 BF ?? ?? ?? 00 }
	$a1 = { BF 00 ?? 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 ?? ?? ?? 00 8B 30 8B 78 04 BB ?? ?? ?? 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 5E EB DB B9 ?? ?? 00 00 BE 00 ?? ?? 00 EB 01 00 BF ?? ?? ?? 00 EB 21 00 ?? ?? 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 00 C0 00 F3 A4 E9 ?? ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 00 C0 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Obsidiumv1331ObsidiumSoftwareh
{
strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv09781
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }

condition:
		$a0 at entrypoint
}
	
	
rule GameGuardv20065xxexe
{
strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

condition:
		$a0 at entrypoint
}
	
	
rule PECompactv09782
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85 }

condition:
		$a0 at entrypoint
}
	
	
rule BorlandC1994
{
strings:
		$a0 = { 8C CA 2E 89 ?? ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA A3 ?? ?? 8C }

condition:
		$a0 at entrypoint
}
	
	
rule UPackAltStubDwing
{
strings:
		$a0 = { 60 E8 09 00 00 00 C3 F6 00 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor15byVaskaUsArsignindividualversion210320072215
{
strings:
		$a0 = { 83 2C 24 4F 68 40 A1 14 13 FF 54 24 04 83 44 24 04 4F B8 00 10 14 13 3D 24 C0 14 13 74 06 80 30 2B 40 EB F3 B8 8C 20 18 13 3D B9 27 18 13 74 06 80 30 19 40 EB F3 E8 00 00 00 00 C3 }

condition:
		$a0 at entrypoint
}
	
	
rule MicrosoftWAVAudiofile
{
strings:
		$a0 = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 66 6D 74 }

condition:
		$a0
}
	
	
rule BorlandC1991
{
strings:
		$a0 = { 2E 8C 06 ?? ?? 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F }

condition:
		$a0 at entrypoint
}
	
	
rule VxModificationofHi924
{
strings:
		$a0 = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack108
{
strings:
		$a0 = { 90 90 90 75 01 90 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor226DLLminimumprotection
{
strings:
		$a0 = { 50 8B C6 87 04 24 68 ?? ?? ?? ?? 5E E9 ?? ?? ?? ?? 85 C8 E9 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 0F 81 ?? ?? ?? 00 81 FA ?? ?? ?? ?? 33 D0 E9 ?? ?? ?? 00 0F 8D ?? ?? ?? 00 81 D5 ?? ?? ?? ?? F7 D1 0B 15 ?? ?? ?? ?? C1 C2 ?? 81 C2 ?? ?? ?? ?? 9D E9 ?? ?? ?? ?? C1 E2 ?? C1 E8 ?? 81 EA ?? ?? ?? ?? 13 DA 81 E9 ?? ?? ?? ?? 87 04 24 8B C8 E9 ?? ?? ?? ?? 55 8B EC 83 C4 F8 89 45 FC 8B 45 FC 89 45 F8 8B 45 08 E9 ?? ?? ?? ?? 8B 45 E0 C6 00 00 FF 45 E4 E9 ?? ?? ?? ?? FF 45 E4 E9 ?? ?? ?? 00 F7 D3 0F 81 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 34 24 5E 8B 45 F4 E8 ?? ?? ?? 00 8B 45 F4 8B E5 5D C3 E9 }

condition:
		$a0 at entrypoint
}
	
	
rule yodasProtector102AshkibizDanehlar
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3A 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 C3 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }

condition:
		$a0 at entrypoint
}
	
	
rule PseudoSigner02FSG10
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

condition:
		$a0 at entrypoint
}
	
	