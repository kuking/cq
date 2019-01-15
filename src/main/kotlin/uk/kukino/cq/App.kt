package uk.kukino.cq

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JSON
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.Hex

@Serializable
data class Key(val private: String, val public: String)

fun main(rgs: Array<String>) {
    val ech = ECH() // curve="sect571k1"
    val kp = ech.createKeyPair()

    println("Private: " + ech.privateAsB64(kp.private))
    println(" Public: " + ech.publicAsB64(kp.public))
    println()

    println("16: " + BaseN.B16.encode(BaseN.fromUnsigned(kp.public.encoded)))
    println("16: " + Hex.toHexString(kp.public.encoded))
    println("58: " + BaseN.B58.encode(BaseN.fromUnsigned(kp.public.encoded)))
    println("85: " + BaseN.B85.encode(BaseN.fromUnsigned(kp.public.encoded)))
    println("64: " + Base64.toBase64String(kp.public.encoded))

    val key = Key(ech.privateAsB58(kp.private), ech.publicAsB58(kp.public))
    val serialised = JSON.stringify(Key.serializer(), key)
    println(serialised)
    val key2 = JSON.parse(Key.serializer(), serialised)
    assert(key == key2)

}
