package uk.kukino.cq

import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.Hex

fun main(rgs: Array<String>) {
    val ech = ECH(curve = "sect571k1")
    val kp = ech.createKeyPair()

    println("Private: " + ech.privateAsB64(kp.private))
    println(" Public: " + ech.publicAsB64(kp.public))
    println()

    println("16: " + BaseN.B16.encode(BaseN.fromUnsigned(kp.public.encoded)))
    println("16: " + Hex.toHexString(kp.public.encoded))
    println("58: " + BaseN.B58.encode(BaseN.fromUnsigned(kp.public.encoded)))
    println("85: " + BaseN.B85.encode(BaseN.fromUnsigned(kp.public.encoded)))
    println("64: " + Base64.toBase64String(kp.public.encoded))
}
