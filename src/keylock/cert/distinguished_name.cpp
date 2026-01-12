#include <keylock/cert/distinguished_name.hpp>

#include <algorithm>
#include <cctype>
#include <sstream>

#include <keylock/cert/asn1_utils.hpp>
#include <keylock/cert/asn1_writer.hpp>

namespace keylock::cert {

    namespace {

        struct SpanCursor {
            ByteSpan data;
            size_t offset{0};

            explicit SpanCursor(ByteSpan span) : data(span) {}

            ByteSpan remaining() const { return data.subspan(offset); }

            bool empty() const { return offset >= data.size(); }

            bool advance(size_t count) {
                if (offset + count > data.size()) {
                    return false;
                }
                offset += count;
                return true;
            }
        };

        DistinguishedNameAttribute attribute_from_oid(const Oid &oid) {
            if (oid.nodes == std::vector<uint32_t>{2, 5, 4, 3}) {
                return DistinguishedNameAttribute::CommonName;
            }
            if (oid.nodes == std::vector<uint32_t>{2, 5, 4, 6}) {
                return DistinguishedNameAttribute::CountryName;
            }
            if (oid.nodes == std::vector<uint32_t>{2, 5, 4, 10}) {
                return DistinguishedNameAttribute::OrganizationName;
            }
            if (oid.nodes == std::vector<uint32_t>{2, 5, 4, 11}) {
                return DistinguishedNameAttribute::OrganizationalUnitName;
            }
            if (oid.nodes == std::vector<uint32_t>{2, 5, 4, 8}) {
                return DistinguishedNameAttribute::StateOrProvinceName;
            }
            if (oid.nodes == std::vector<uint32_t>{2, 5, 4, 7}) {
                return DistinguishedNameAttribute::LocalityName;
            }
            return DistinguishedNameAttribute::Unknown;
        }

        Oid oid_from_attribute(DistinguishedNameAttribute attribute) {
            switch (attribute) {
            case DistinguishedNameAttribute::CommonName:
                return {{2, 5, 4, 3}};
            case DistinguishedNameAttribute::CountryName:
                return {{2, 5, 4, 6}};
            case DistinguishedNameAttribute::OrganizationName:
                return {{2, 5, 4, 10}};
            case DistinguishedNameAttribute::OrganizationalUnitName:
                return {{2, 5, 4, 11}};
            case DistinguishedNameAttribute::StateOrProvinceName:
                return {{2, 5, 4, 8}};
            case DistinguishedNameAttribute::LocalityName:
                return {{2, 5, 4, 7}};
            case DistinguishedNameAttribute::Unknown:
            default:
                throw std::runtime_error("Cannot convert Unknown or invalid DistinguishedNameAttribute to OID");
            }
        }

        bool is_printable_string(std::string_view str) {
            for (char c : str) {
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
                    continue;
                }
                switch (c) {
                case ' ':
                case '\'':
                case '(':
                case ')':
                case '+':
                case ',':
                case '-':
                case '.':
                case '/':
                case ':':
                case '=':
                case '?':
                    continue;
                default:
                    return false;
                }
            }
            return true;
        }

        std::vector<uint8_t> encode_directory_string(const AttributeTypeAndValue &attr) {
            if (attr.attribute == DistinguishedNameAttribute::CountryName && attr.value.size() == 2 &&
                std::all_of(attr.value.begin(), attr.value.end(),
                            [](char c) { return std::isalpha(static_cast<unsigned char>(c)); })) {
                std::string upper = attr.value;
                std::transform(upper.begin(), upper.end(), upper.begin(),
                               [](unsigned char c) { return std::toupper(c); });
                return der::encode_printable_string(upper);
            }
            if (is_printable_string(attr.value)) {
                return der::encode_printable_string(attr.value);
            }
            return der::encode_utf8_string(attr.value);
        }

        std::string_view trim(std::string_view view) {
            while (!view.empty() && std::isspace(static_cast<unsigned char>(view.front()))) {
                view.remove_prefix(1);
            }
            while (!view.empty() && std::isspace(static_cast<unsigned char>(view.back()))) {
                view.remove_suffix(1);
            }
            return view;
        }

        std::optional<DistinguishedNameAttribute> attribute_from_string(std::string_view token) {
            if (token == "CN") {
                return DistinguishedNameAttribute::CommonName;
            }
            if (token == "C") {
                return DistinguishedNameAttribute::CountryName;
            }
            if (token == "O") {
                return DistinguishedNameAttribute::OrganizationName;
            }
            if (token == "OU") {
                return DistinguishedNameAttribute::OrganizationalUnitName;
            }
            if (token == "ST" || token == "S") {
                return DistinguishedNameAttribute::StateOrProvinceName;
            }
            if (token == "L") {
                return DistinguishedNameAttribute::LocalityName;
            }
            return std::nullopt;
        }

        struct ParsedDn {
            bool success;
            std::vector<RelativeDistinguishedName> rdns;
            std::string error;
        };

        ParsedDn parse_dn_string(std::string_view input) {
            std::vector<RelativeDistinguishedName> rdns;
            std::string current;
            size_t start = 0;
            while (start <= input.size()) {
                size_t end = input.find(',', start);
                if (end == std::string_view::npos) {
                    end = input.size();
                }
                auto component = trim(input.substr(start, end - start));
                if (!component.empty()) {
                    RelativeDistinguishedName rdn;
                    size_t sub_start = 0;
                    do {
                        size_t sub_end = component.find('+', sub_start);
                        auto pair = trim(component.substr(sub_start, sub_end == std::string_view::npos
                                                                         ? component.size() - sub_start
                                                                         : sub_end - sub_start));
                        auto eq_pos = pair.find('=');
                        if (eq_pos == std::string_view::npos) {
                            return {false, {}, "invalid DN component"};
                        }
                        auto attr = trim(pair.substr(0, eq_pos));
                        auto value = trim(pair.substr(eq_pos + 1));
                        auto attribute = attribute_from_string(attr);
                        if (!attribute.has_value()) {
                            return {false, {}, "unsupported DN attribute"};
                        }
                        AttributeTypeAndValue atv{};
                        atv.attribute = *attribute;
                        atv.oid = oid_from_attribute(*attribute);
                        atv.value = std::string(value);
                        rdn.push_back(std::move(atv));
                        if (sub_end == std::string_view::npos) {
                            break;
                        }
                        sub_start = sub_end + 1;
                    } while (true);
                    rdns.push_back(std::move(rdn));
                }
                if (end == input.size()) {
                    break;
                }
                start = end + 1;
            }
            if (rdns.empty()) {
                return {false, {}, "DN string empty"};
            }
            return {true, std::move(rdns), {}};
        }

        std::vector<uint8_t> encode_name(const std::vector<RelativeDistinguishedName> &rdns) {
            std::vector<std::vector<uint8_t>> rdn_blocks;
            for (const auto &rdn : rdns) {
                std::vector<std::vector<uint8_t>> atvs;
                for (const auto &atv : rdn) {
                    auto oid = der::encode_oid(atv.oid);
                    auto value = encode_directory_string(atv);
                    auto seq = der::encode_sequence(der::concat({oid, value}));
                    atvs.push_back(std::move(seq));
                }
                auto set_block = der::encode_set(der::concat(atvs));
                rdn_blocks.push_back(std::move(set_block));
            }
            return der::encode_sequence(der::concat(rdn_blocks));
        }

    } // namespace

    DistinguishedName::DistinguishedName(std::vector<uint8_t> der_bytes)
        : der_(std::move(der_bytes)), parsed_(false), encoded_(true) {}

    const std::vector<uint8_t> &DistinguishedName::der() const {
        ensure_encoded();
        return der_;
    }

    const std::vector<RelativeDistinguishedName> &DistinguishedName::rdns() const {
        ensure_parsed();
        return rdns_;
    }

    DistinguishedName::Result DistinguishedName::from_string(std::string_view input) {
        auto parsed = parse_dn_string(input);
        if (!parsed.success) {
            return Result::failure(parsed.error);
        }
        DistinguishedName dn;
        dn.rdns_ = std::move(parsed.rdns);
        dn.parsed_ = true;
        dn.encoded_ = false;
        return Result::ok(std::move(dn));
    }

    void DistinguishedName::ensure_encoded() const {
        if (encoded_) {
            return;
        }
        der_ = encode_name(rdns_);
        encoded_ = true;
    }

    void DistinguishedName::ensure_parsed() const {
        if (parsed_) {
            return;
        }
        parsed_ = true;
        rdns_.clear();
        if (der_.empty()) {
            return;
        }

        ByteSpan span(der_.data(), der_.size());
        auto seq_result = parse_sequence(span);
        if (!seq_result.success) {
            return;
        }
        SpanCursor cursor(seq_result.value);

        while (!cursor.empty()) {
            auto set_result = parse_set(cursor.remaining());
            if (!set_result.success) {
                rdns_.clear();
                return;
            }
            SpanCursor set_cursor(set_result.value);
            RelativeDistinguishedName rdn;

            while (!set_cursor.empty()) {
                auto atv_seq = parse_sequence(set_cursor.remaining());
                if (!atv_seq.success) {
                    rdns_.clear();
                    return;
                }
                SpanCursor atv_cursor(atv_seq.value);

                auto oid_result = parse_oid(atv_cursor.remaining());
                if (!oid_result.success) {
                    rdns_.clear();
                    return;
                }
                atv_cursor.advance(oid_result.bytes_consumed);

                auto value_result = parse_directory_string(atv_cursor.remaining());
                if (!value_result.success) {
                    rdns_.clear();
                    return;
                }
                atv_cursor.advance(value_result.bytes_consumed);

                if (!atv_cursor.empty()) {
                    rdns_.clear();
                    return;
                }

                AttributeTypeAndValue entry{};
                entry.oid = oid_result.value;
                entry.attribute = attribute_from_oid(entry.oid);
                entry.value = value_result.value;
                rdn.push_back(std::move(entry));

                set_cursor.advance(atv_seq.bytes_consumed);
            }

            rdns_.push_back(std::move(rdn));
            cursor.advance(set_result.bytes_consumed);
        }
    }

    std::optional<std::string> DistinguishedName::first(DistinguishedNameAttribute attribute) const {
        ensure_parsed();
        for (const auto &rdn : rdns_) {
            for (const auto &entry : rdn) {
                if (entry.attribute == attribute) {
                    return entry.value;
                }
            }
        }
        return std::nullopt;
    }

    std::string DistinguishedName::to_string() const {
        ensure_parsed();
        auto attr_name = [](DistinguishedNameAttribute attribute) {
            switch (attribute) {
            case DistinguishedNameAttribute::CommonName:
                return "CN";
            case DistinguishedNameAttribute::CountryName:
                return "C";
            case DistinguishedNameAttribute::OrganizationName:
                return "O";
            case DistinguishedNameAttribute::OrganizationalUnitName:
                return "OU";
            case DistinguishedNameAttribute::StateOrProvinceName:
                return "ST";
            case DistinguishedNameAttribute::LocalityName:
                return "L";
            default:
                return "OID";
            }
        };

        std::ostringstream oss;
        bool first_attr = true;
        for (const auto &rdn : rdns_) {
            for (const auto &entry : rdn) {
                if (!first_attr) {
                    oss << ", ";
                }
                first_attr = false;
                oss << attr_name(entry.attribute) << "=" << entry.value;
            }
        }
        return oss.str();
    }

} // namespace keylock::cert
