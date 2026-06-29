rule SilentNet_Java_JAR
{
    meta:
        author = "Farish"
        description = "Detects SilentNet Java malware JAR"
        family = "SilentNet"
        confidence = "Medium"
        date = "2026-06-28"
        hash_SHA256 = "6b3d90c90c03d4ebb10f6e76f32d5f12dbae8e01d42518060e14f8968e32dc15"
        reference = "https://bazaar.abuse.ch/sample/6b3d90c90c03d4ebb10f6e76f32d5f12dbae8e01d42518060e14f8968e32dc15"

    strings:

        $c1 = "com/github/ltPFJTIjJ.class" ascii
        $c2 = "com/github/HYCxXNej.class" ascii
        $c3 = "com/github/qiez_unbed_vowo.class" ascii
        $c4 = "com/github/aEjghhhsj.class" ascii

    condition:

        uint32(0) == 0x04034B50 and

        all of them
}
