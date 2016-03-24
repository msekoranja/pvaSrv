/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvAccessCPP is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef CASECURITY_H
#define CASECURITY_H

#ifdef epicsExportSharedSymbols
#   define casecurityEpicsExportSharedSymbols
#   undef epicsExportSharedSymbols
#endif

#include <string>

#include <asLib.h>

#include <pv/pvData.h>
#include <pv/security.h>


#ifdef casecurityEpicsExportSharedSymbols
#   define epicsExportSharedSymbols
#	undef casecurityEpicsExportSharedSymbols
#endif

#include <shareLib.h>

namespace epics {
    namespace pvaSrv {

/*
    class CAServerChannelSecuritySession :
        public epics::pvAccess::ChannelSecuritySession
    {
    public:
        POINTER_DEFINITIONS(CAServerChannelSecuritySession);

        CAServerChannelSecuritySession(std::string const & channelName,
                                       const char * user,
                                       char * host)
            throw (epics::pvAccess::SecurityException);

        virtual ~CAServerChannelSecuritySession();

        /// closes this session
        virtual void close();

        // for every authroizeCreate... a release() must be called
        virtual void release(epics::pvAccess::pvAccessID ioid) {
            // noop
        }

        // bitSet w/ one bit
        virtual epics::pvData::Status authorizeCreateChannelProcess(
                epics::pvAccess::pvAccessID ioid, epics::pvData::PVStructure::shared_pointer const &) {
            return epics::pvData::Status::Ok;
        }

        virtual epics::pvData::Status authorizeProcess(epics::pvAccess::pvAccessID) {
            return epics::pvData::Status::Ok;
        }

        // bitSet w/ one bit (allowed, not allowed) and rest of the bit per field
        virtual epics::pvData::Status authorizeCreateChannelGet(
                epics::pvAccess::pvAccessID, epics::pvData::PVStructure::shared_pointer const &) {
            return epics::pvData::Status::Ok;
        }

        virtual epics::pvData::Status authorizeGet(epics::pvAccess::pvAccessID) {
            if (!asCheckGet(m_asClientPvt))
                return m_noAccessStatus;
            else
                return epics::pvData::Status::Ok;
        }

        // read: bitSet w/ one bit (allowed, not allowed) and rest of the bit per field
        // write: bitSet w/ one bit (allowed, not allowed) and rest of the bit per field
        virtual epics::pvData::Status authorizeCreateChannelPut(
                epics::pvAccess::pvAccessID, epics::pvData::PVStructure::shared_pointer const &) {
            return epics::pvData::Status::Ok;
        }

        virtual epics::pvData::Status authorizePut(
                epics::pvAccess::pvAccessID,
                epics::pvData::PVStructure::shared_pointer const &,
                epics::pvData::BitSet::shared_pointer const &) {
            if (!asCheckPut(m_asClientPvt))
                return m_noAccessStatus;
            else
                return epics::pvData::Status::Ok;
        }

        // read: bitSet w/ one bit (allowed, not allowed) and rest of the bit per field
        // write: bitSet w/ one bit (allowed, not allowed) and rest of the bit per field
        // process: bitSet w/ one bit (allowed, not allowed)
        virtual epics::pvData::Status authorizeCreateChannelPutGet(
                epics::pvAccess::pvAccessID, epics::pvData::PVStructure::shared_pointer const &) {
            return epics::pvData::Status::Ok;
        }

        virtual epics::pvData::Status authorizePutGet(
                epics::pvAccess::pvAccessID,
                epics::pvData::PVStructure::shared_pointer const &,
                epics::pvData::BitSet::shared_pointer const &) {
            if (!asCheckGet(m_asClientPvt) || !asCheckPut(m_asClientPvt))
                return m_noAccessStatus;
            else
                return epics::pvData::Status::Ok;
        }

        // bitSet w/ one bit
        virtual epics::pvData::Status authorizeCreateChannelRPC(
                epics::pvAccess::pvAccessID, epics::pvData::PVStructure::shared_pointer const &) {
            return epics::pvData::Status::Ok;
        }

        // one could authorize per operation basis
        virtual epics::pvData::Status authorizeRPC(
                epics::pvAccess::pvAccessID, epics::pvData::PVStructure::shared_pointer const &) {
            return epics::pvData::Status::Ok;
        }

        // read: bitSet w/ one bit (allowed, not allowed) and rest of the bit per field
        virtual epics::pvData::Status authorizeCreateMonitor(
                epics::pvAccess::pvAccessID, epics::pvData::PVStructure::shared_pointer const &) {
            return epics::pvData::Status::Ok;
        }

        virtual epics::pvData::Status authorizeMonitor(epics::pvAccess::pvAccessID) {
            if (!asCheckGet(m_asClientPvt))
                return m_noAccessStatus;
            else
                return epics::pvData::Status::Ok;
        }

        // read: bitSet w/ one bit (allowed, not allowed) and rest put/get/set length
        virtual epics::pvData::Status authorizeCreateChannelArray(
                epics::pvAccess::pvAccessID, epics::pvData::PVStructure::shared_pointer const &) {
            return epics::pvData::Status::Ok;
        }

        // use authorizeGet
        virtual epics::pvData::Status authorizePut(
                epics::pvAccess::pvAccessID, epics::pvData::PVArray::shared_pointer const &) {
            if (!asCheckPut(m_asClientPvt))
                return m_noAccessStatus;
            else
                return epics::pvData::Status::Ok;
        }

        virtual epics::pvData::Status authorizeSetLength(epics::pvAccess::pvAccessID) {
            return epics::pvData::Status::Ok;
        }

        // introspection authorization
        virtual epics::pvData::Status authorizeGetField(epics::pvAccess::pvAccessID, std::string const &) {
            return epics::pvData::Status::Ok;
        }


    private:

        static epics::pvData::Status m_noAccessStatus;

        struct dbChannel *m_dbChannel;
        ASCLIENTPVT m_asClientPvt;
    };
*/
/*
    struct NoChannelException : public epics::pvAccess::SecurityException
    {
        NoChannelException() : SecurityException("No such channel") {}
    };
*/
    class epicsShareClass CAServerSecuritySession :
        public epics::pvAccess::SecuritySession
    {
    public:
        POINTER_DEFINITIONS(CAServerSecuritySession);

        static epics::pvData::Structure::const_shared_pointer caAuthorizationDataStructure;

        CAServerSecuritySession(epics::pvAccess::SecurityPlugin::shared_pointer const & parent,
                                std::string const & user,
                                std::string const & host) :
            m_parent(parent),
            m_user(user)
        {
            strncpy(m_host, host.c_str(), 256-1);
            m_authorizationData = epics::pvData::getPVDataCreate()->createPVStructure(caAuthorizationDataStructure);

            m_authorizationData->getSubField<epics::pvData::PVString>("authority")->put(parent->getId());
            m_authorizationData->getSubField<epics::pvData::PVString>("authorizationID")->put(m_user);
            m_authorizationData->getSubField<epics::pvData::PVString>("host")->put(m_host);
        }

        virtual ~CAServerSecuritySession() {}

        // optional (can be null) initialization data for the remote party
        // client to server
        virtual epics::pvData::PVField::shared_pointer initializationData() {
            return epics::pvData::PVField::shared_pointer();
        }

        virtual epics::pvData::PVStructure::shared_pointer authorizationData() {
            return m_authorizationData;
        }

        // get parent
        virtual std::tr1::shared_ptr<epics::pvAccess::SecurityPlugin> getSecurityPlugin() {
            return m_parent;
        }

        // can be called any time, for any reason
        virtual void messageReceived(epics::pvData::PVField::shared_pointer const & data) {
            // noop
        }

        /// closes this session
        virtual void close() {
            m_parent.reset();
        }

    private:
        epics::pvAccess::SecurityPlugin::shared_pointer m_parent;
        std::string m_user;
        char m_host[256];
        epics::pvData::PVStructure::shared_pointer m_authorizationData;
    };




    class epicsShareClass CAServerSecurityPlugin :
            public epics::pvAccess::SecurityPlugin,
            public std::tr1::enable_shared_from_this<CAServerSecurityPlugin>
    {
    public:
        POINTER_DEFINITIONS(CAServerSecurityPlugin);

        virtual ~CAServerSecurityPlugin() {}

        virtual std::string getId() const {
            return "ca";
        }

        virtual std::string getDescription() const {
            return "CA server security plug-in";
        }

        virtual bool isValidFor(osiSockAddr const & /*remoteAddress*/) const {
            return true;
        }

        virtual epics::pvAccess::SecuritySession::shared_pointer createSession(
                osiSockAddr const & /*remoteAddress*/,
                epics::pvAccess::SecurityPluginControl::shared_pointer const & control,
                epics::pvData::PVField::shared_pointer const & data);

    };


    }
}

#endif // CASECURITY_H
