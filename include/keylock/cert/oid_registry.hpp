#pragma once

#include <optional>
#include <span>

#include <keylock/cert/asn1_common.hpp>

namespace keylock::cert {

    /**
     * RFC-defined object identifiers that we care about for certificates.
     * Provides helpers to translate parsed OIDs into strongly typed enums.
     */

    SignatureAlgorithmId find_sig_alg_by_oid(const Oid &oid);
    std::optional<hash::Algorithm> find_hash_by_oid(const Oid &oid);
    CurveId find_curve_by_oid(const Oid &oid);
    ExtensionId find_extension_by_oid(const Oid &oid);
    std::optional<Oid> oid_for_signature(SignatureAlgorithmId id);
    std::optional<Oid> oid_for_curve(CurveId id);
    std::optional<Oid> oid_for_extension(ExtensionId id);
    std::optional<Oid> oid_for_hash(hash::Algorithm algorithm);

} // namespace keylock::cert
