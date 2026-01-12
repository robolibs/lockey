#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <keylock/cert/asn1_common.hpp>

namespace keylock::cert {

    enum class DistinguishedNameAttribute {
        Unknown = 0,
        CommonName,
        CountryName,
        OrganizationName,
        OrganizationalUnitName,
        StateOrProvinceName,
        LocalityName
    };

    struct AttributeTypeAndValue {
        Oid oid{};
        DistinguishedNameAttribute attribute{DistinguishedNameAttribute::Unknown};
        std::string value;
    };

    using RelativeDistinguishedName = std::vector<AttributeTypeAndValue>;

    class DistinguishedName {
      public:
        struct Result;

        DistinguishedName() = default;
        explicit DistinguishedName(std::vector<uint8_t> der_bytes);

        static Result from_string(std::string_view input);

        [[nodiscard]] const std::vector<uint8_t> &der() const;
        [[nodiscard]] const std::vector<RelativeDistinguishedName> &rdns() const;

        [[nodiscard]] std::optional<std::string> first(DistinguishedNameAttribute attribute) const;
        [[nodiscard]] std::string to_string() const;

      private:
        void ensure_parsed() const;
        void ensure_encoded() const;

        mutable std::vector<uint8_t> der_;
        mutable bool parsed_{false};
        mutable bool encoded_{false};
        mutable std::vector<RelativeDistinguishedName> rdns_;
    };

    struct DistinguishedName::Result {
        bool success{};
        DistinguishedName value{};
        std::string error{};

        static Result failure(std::string message) { return Result{false, {}, std::move(message)}; }
        static Result ok(DistinguishedName value) { return Result{true, std::move(value), {}}; }
    };

} // namespace keylock::cert
