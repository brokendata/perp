"""Synthetic structured hashes; no real account details or passwords are committed."""
import unittest
from potfile_parser import parse_record


class PotfileParserTests(unittest.TestCase):
    def kerberos23(self):
        return b"$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQLSvc/server.example.test:1433*$" + b"a" * 32 + b"$" + b"b" * 128

    def test_kerberos_port_is_part_of_hash(self):
        hashed = self.kerberos23()
        for password in (b"Secret42!", b"svc", b"pass:word:with:colons", b"p$with$dollars", b""):
            self.assertEqual(parse_record(hashed + b":" + password), (hashed, password))

    def test_compact_tgs_and_aes(self):
        hashes = [b"$krb5tgs$23$" + b"a" * 32 + b"$" + b"b" * 128]
        for etype in (b"17", b"18"):
            hashes.append(b"$krb5tgs$" + etype + b"$svc$EXAMPLE.TEST$*MSSQLSvc/server:1433*$" + b"a" * 24 + b"$" + b"b" * 128)
            hashes.append(b"$krb5tgs$" + etype + b"$svc$EXAMPLE.TEST$" + b"a" * 24 + b"$" + b"b" * 128)
        for hashed in hashes:
            self.assertEqual(parse_record(hashed + b":pw:with:colon"), (hashed, b"pw:with:colon"))

    def test_asrep_account_separator_is_part_of_hash(self):
        hashed = b"$krb5asrep$23$svc@EXAMPLE.TEST:" + b"a" * 32 + b"$" + b"b" * 128
        self.assertEqual(parse_record(hashed + b":pw"), (hashed, b"pw"))

    def test_netntlm_username_domain_and_responses_are_not_password(self):
        hashes = [b"svc::EXAMPLE:" + b"a" * 16 + b":" + b"b" * 32 + b":" + b"c" * 64,
                  b"svc::EXAMPLE:" + b"a" * 48 + b":" + b"b" * 48 + b":" + b"c" * 16]
        for hashed in hashes:
            self.assertEqual(parse_record(hashed + b":Password!"), (hashed, b"Password!"))

    def test_unknown_multifield_requires_declared_layout(self):
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            parse_record(b"hash:salt:pw")
        self.assertEqual(parse_record(b"hash:salt:pw", field=2), (b"hash:salt", b"pw"))

    def test_hashcat_dialect_matches_native_last_separator_and_hex(self):
        self.assertEqual(parse_record(b"hash:salt:user:$HEX[706173733a776f7264]", dialect="hashcat"),
                         (b"hash:salt:user", b"pass:word"))
        self.assertEqual(parse_record(self.kerberos23() + b":$HEX[413aff]", dialect="hashcat")[1], b"A:\xff")

    def test_malformed_or_hash_only_kerberos_does_not_fall_back(self):
        for line in (self.kerberos23(), b"$krb5tgs$23$bad:1433", self.kerberos23().replace(b"b" * 128, b"nothex") + b":pw"):
            with self.assertRaises(ValueError):
                parse_record(line)

    def test_wrong_exports_do_not_silently_discard_fields(self):
        with self.assertRaises(ValueError):
            parse_record(b"user:hash:pw:trailing-metadata")


if __name__ == "__main__":
    unittest.main()
