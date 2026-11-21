/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.vitorpamplona.marmot.features.devicePairing

/**
 * One entry of Matrix's SAS emoji table (`features/device-pairing.md` Appendix A, from matrix-spec
 * `data-definitions/sas-emoji.json` at `7aaeac07`). [unicode] is Matrix's spelling (`U+1F436`,
 * `U+2601U+FE0F`); [emoji] is built from it, so no raw emoji sits in source.
 */
class SasEmoji(
    /** Its position in the table, the 6-bit value that selects it. */
    val number: Int,
    /** Matrix's English description: show it with the picture and give it to screen readers. */
    val description: String,
    val unicode: String,
) {
    val emoji: String =
        buildString {
            unicode.split("U+").filter { it.isNotEmpty() }.forEach { hex ->
                val cp = hex.toInt(16)
                if (cp >= 0x10000) {
                    val v = cp - 0x10000
                    append((0xD800 + (v shr 10)).toChar())
                    append((0xDC00 + (v and 0x3FF)).toChar())
                } else {
                    append(cp.toChar())
                }
            }
        }

    override fun toString() = "$emoji $description"

    companion object {
        /** The 64 entries, indexed by number. */
        val TABLE: List<SasEmoji> =
            listOf(
                SasEmoji(0, "Dog", "U+1F436"),
                SasEmoji(1, "Cat", "U+1F431"),
                SasEmoji(2, "Lion", "U+1F981"),
                SasEmoji(3, "Horse", "U+1F40E"),
                SasEmoji(4, "Unicorn", "U+1F984"),
                SasEmoji(5, "Pig", "U+1F437"),
                SasEmoji(6, "Elephant", "U+1F418"),
                SasEmoji(7, "Rabbit", "U+1F430"),
                SasEmoji(8, "Panda", "U+1F43C"),
                SasEmoji(9, "Rooster", "U+1F413"),
                SasEmoji(10, "Penguin", "U+1F427"),
                SasEmoji(11, "Turtle", "U+1F422"),
                SasEmoji(12, "Fish", "U+1F41F"),
                SasEmoji(13, "Octopus", "U+1F419"),
                SasEmoji(14, "Butterfly", "U+1F98B"),
                SasEmoji(15, "Flower", "U+1F337"),
                SasEmoji(16, "Tree", "U+1F333"),
                SasEmoji(17, "Cactus", "U+1F335"),
                SasEmoji(18, "Mushroom", "U+1F344"),
                SasEmoji(19, "Globe", "U+1F30F"),
                SasEmoji(20, "Moon", "U+1F319"),
                SasEmoji(21, "Cloud", "U+2601U+FE0F"),
                SasEmoji(22, "Fire", "U+1F525"),
                SasEmoji(23, "Banana", "U+1F34C"),
                SasEmoji(24, "Apple", "U+1F34E"),
                SasEmoji(25, "Strawberry", "U+1F353"),
                SasEmoji(26, "Corn", "U+1F33D"),
                SasEmoji(27, "Pizza", "U+1F355"),
                SasEmoji(28, "Cake", "U+1F382"),
                SasEmoji(29, "Heart", "U+2764U+FE0F"),
                SasEmoji(30, "Smiley", "U+1F600"),
                SasEmoji(31, "Robot", "U+1F916"),
                SasEmoji(32, "Hat", "U+1F3A9"),
                SasEmoji(33, "Glasses", "U+1F453"),
                SasEmoji(34, "Spanner", "U+1F527"),
                SasEmoji(35, "Santa", "U+1F385"),
                SasEmoji(36, "Thumbs Up", "U+1F44D"),
                SasEmoji(37, "Umbrella", "U+2602U+FE0F"),
                SasEmoji(38, "Hourglass", "U+231B"),
                SasEmoji(39, "Clock", "U+23F0"),
                SasEmoji(40, "Gift", "U+1F381"),
                SasEmoji(41, "Light Bulb", "U+1F4A1"),
                SasEmoji(42, "Book", "U+1F4D5"),
                SasEmoji(43, "Pencil", "U+270FU+FE0F"),
                SasEmoji(44, "Paperclip", "U+1F4CE"),
                SasEmoji(45, "Scissors", "U+2702U+FE0F"),
                SasEmoji(46, "Lock", "U+1F512"),
                SasEmoji(47, "Key", "U+1F511"),
                SasEmoji(48, "Hammer", "U+1F528"),
                SasEmoji(49, "Telephone", "U+260EU+FE0F"),
                SasEmoji(50, "Flag", "U+1F3C1"),
                SasEmoji(51, "Train", "U+1F682"),
                SasEmoji(52, "Bicycle", "U+1F6B2"),
                SasEmoji(53, "Aeroplane", "U+2708U+FE0F"),
                SasEmoji(54, "Rocket", "U+1F680"),
                SasEmoji(55, "Trophy", "U+1F3C6"),
                SasEmoji(56, "Ball", "U+26BD"),
                SasEmoji(57, "Guitar", "U+1F3B8"),
                SasEmoji(58, "Trumpet", "U+1F3BA"),
                SasEmoji(59, "Bell", "U+1F514"),
                SasEmoji(60, "Anchor", "U+2693"),
                SasEmoji(61, "Headphones", "U+1F3A7"),
                SasEmoji(62, "Folder", "U+1F4C1"),
                SasEmoji(63, "Pin", "U+1F4CC"),
            )

        /**
         * The seven emoji for [sasBytes]: the first 42 bits, most significant first, as seven 6-bit
         * indices into [TABLE].
         */
        fun numbers(sasBytes: ByteArray): List<Int> {
            require(sasBytes.size >= 6) { "a SAS code needs 6 bytes" }
            var bits = 0L
            for (i in 0 until 6) bits = (bits shl 8) or (sasBytes[i].toLong() and 0xff)
            return List(7) { index -> ((bits shr (42 - 6 * index)) and 0x3f).toInt() }
        }

        fun of(sasBytes: ByteArray): List<SasEmoji> = numbers(sasBytes).map { TABLE[it] }
    }
}
