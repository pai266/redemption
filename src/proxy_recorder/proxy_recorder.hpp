/*
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Product name: redemption, a FLOSS RDP proxy
   Copyright (C) Wallix 2018
   Author(s): David Fort

   A proxy that will capture all the traffic to the target
*/

#pragma once

#include "transport/recorder_transport.hpp"
#include "core/RDP/x224.hpp"
#include "core/RDP/tpdu_buffer.hpp"
#include "core/RDP/nla/credssp.hpp"
#include "proxy_recorder/extract_user_domain.hpp"

#include <string>
#include <memory>


class NlaTeeTransport;
class NegoClient;
class NegoServer;
class TimeBase;


/** @brief a front connection with a RDP client */
class ProxyRecorder
{
    X224::CR_TPDU_Data front_CR_TPDU;

    using PacketType = RecorderFile::PacketType;

    std::pair<PasswordCallback,array_md4> get_password_hash(bytes_view user_av, bytes_view domain_av, std::string_view  nla_username, std::string_view nla_password)
    {
        LOG(LOG_INFO, "NTLM Check identity");
        hexdump_d(user_av);

        auto [username, domain] = extract_user_domain(nla_username);
        // from protocol
        auto tmp_utf8_user = UTF16toResizableUTF8_zstring<std::vector<char>>(user_av);
        auto u8user = zstring_view::from_null_terminated(tmp_utf8_user);
        auto tmp_utf8_domain = UTF16toResizableUTF8_zstring<std::vector<char>>(domain_av);
        auto u8domain = zstring_view::from_null_terminated(tmp_utf8_domain);

        LOG(LOG_INFO, "NTML IDENTITY(message): identity.User=%s identity.Domain=%s username=%.*s, domain=%.*s",
            u8user, u8domain,
            int(username.size()), username.data(), int(domain.size()), domain.data());

        if (u8domain.size() == 0){
            auto [identity_username, identity_domain] = extract_user_domain(u8user.to_sv());

            bool user_match = (username == identity_username);
            bool domain_match = (domain == identity_domain);

            if (user_match && domain_match){
                LOG(LOG_INFO, "known identity");
                return {PasswordCallback::Ok, Md4(::UTF8toResizableUTF16<std::vector<uint8_t>>(nla_password))};
            }
        }
        else if (u8user.to_sv() == username && u8domain.to_sv() == domain){
            return {PasswordCallback::Ok, Md4(::UTF8toResizableUTF16<std::vector<uint8_t>>(nla_password))};
        }

        LOG(LOG_ERR, "Ntlm: unknwon identity");
        return {PasswordCallback::Error, {}};
    }

public:
    ProxyRecorder(
        NlaTeeTransport & back_nla_tee_trans,
        RecorderFile & outFile,
        TimeBase & time_base,
        const char * host,
        bool enable_kerberos,
        uint64_t verbosity
    );

    ~ProxyRecorder();

    void front_step1(Transport & frontConn);
    void back_step1(writable_u8_array_view key, Transport & backConn, std::string const& nla_username, std::string nla_password);
    void front_nla(Transport & frontConn, std::string_view  nla_username, std::string_view nla_password);
    void front_initial_pdu_negociation(Transport & backConn, bool is_nla);
    void back_nla_negociation(Transport & backConn);
    void back_initial_pdu_negociation(Transport & frontConn, bool is_nla);

public:
    enum class PState : unsigned {
        NEGOCIATING_FRONT_STEP1,
        NEGOCIATING_FRONT_NLA,
        NEGOCIATING_BACK_NLA,
        NEGOCIATING_FRONT_INITIAL_PDU,
        NEGOCIATING_BACK_INITIAL_PDU,
        FORWARD
    } pstate = PState::NEGOCIATING_FRONT_STEP1;


    NlaTeeTransport & back_nla_tee_trans;
    RecorderFile & outFile;
    TimeBase & time_base;
    const char * host;

    TpduBuffer frontBuffer;
    TpduBuffer backBuffer;

    std::unique_ptr<NegoClient> nego_client;
    std::unique_ptr<NegoServer> nego_server;

    bool enable_kerberos;
    bool is_tls_client = false;
    bool is_nla_client = false;
    uint64_t verbosity;
};

