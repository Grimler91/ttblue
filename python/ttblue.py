#!/usr/bin/python2
# -*- coding: utf-8 -*-
from bluepy import btle
import struct, collections, random, time, sys
import requests
import cStringIO as StringIO
from binascii import hexlify, unhexlify
from datetime import datetime
from crc16_modbus import crc16_modbus as tt_crc16_streamer, _crc16_modbus as tt_crc16

v1_handles = {
    'ppcp'       : 0x0b,
    'passcode'   : 0x32,
    'magic'      : 0x35,
    'cmd_status' : 0x25,
    'length'     : 0x28,
    'transfer'   : 0x2b,
    'check'      : 0x2e
}

v2_handles = {
    'ppcp'       : 0x00,
    'passcode'   : 0x82,
    'magic'      : 0x85,
    'cmd_status' : 0x72,
    'length'     : 0x75,
    'transfer'   : 0x78,
    'check'      : 0x7b
}

v1_files = {
    'hostname'       : 0x00020002,
    'preference'     : 0x00f20000,
    'manifest'       : 0x00850000,
    'activity_start' : 0x00910000,
    'gps_status'     : 0x00020001,
    'quickgps'       : 0x00010100
};

v2_files = {
    'hostname'       : 0x00020003,
    'preference'     : 0x00f20000,
    'manifest'       : 0x00850000,
    'activity_start' : 0x00910000,
    'gps_status'     : 0x00020001,
    'quickgps'       : 0x00010100
};

magic_bytes = bytearray((0x01, 0x19, 0, 0, 0x01, 0x17, 0, 0))

handle = v2_handles
file = v2_files

class MyDelegate(btle.DefaultDelegate):
    __slots__ = ('handle','data','idata')
    def __init__(self):
        btle.DefaultDelegate.__init__(self)
        self.handle = self.data = self.idata = None
    def handleNotification(self, cHandle, data):
        l2s = {1:'B',2:'H',4:'L',8:'Q'}
        self.handle = cHandle
        self.data = data
        self.idata = struct.unpack('<'+l2s[len(data)], data)[0] if len(data) in l2s else None

h_d_id = collections.namedtuple('h_d_id', 'handle data idata')

def hnone(n, d=4):
    return ("0x%%0%dx" % d % n) if n is not None else None

def rda(p, handle=None, data=None, idata=None, timeout=1.0):
    p.delegate.handle, p.delegate.data, p.delegate.idata = None, None, None
    p.waitForNotifications(timeout)
    h,d,id = p.delegate.handle, p.delegate.data, p.delegate.idata
    if handle not in (None, h) or data not in (None, d) or idata not in (None, id):
        raise AssertionError, "expected (%s,%s,%s) got (%s,%s,%s)" % (hnone(handle), repr(data), hnone(idata), hnone(h), repr(d), hnone(id))
    return h_d_id(h,d,id)

########################################

def tt_send_command(p, cmdno):
    for tries in range(0,10):
        p.wr(handle['cmd_status'], cmdno, True)
        h, d, id = rda(p)
        if h==handle['cmd_status'] and id==1:
            return tries
        else:
            print "command %02x%02x%02x%02x failed %d times with %s, will retry" % (cmdno[0], cmdno[1], cmdno[2], cmdno[3], tries+1, ((hnone(h),repr(d),hnone(id))))
            time.sleep(1)
    return None

def tt_read_file(p, fileno, outf, limit=None, debug=False):
    # strange ordering: file 0x001234ab (ttwatch naming) becomes 0012ab34
    assert (fileno>>24)==0
    cmdno = bytearray((1, (fileno>>16)&0xff, fileno&0xff, (fileno>>8)&0xff))

    tt_send_command(p, cmdno)
    l = rda(p, handle['length']).idata      # 0x28 = length in/out

    counter = 0
    startat = time.time()
    checker = tt_crc16_streamer()
    for ii in range(0, l, 256*20-2):
        # read up to 256*20-2 data bytes in 20B chunks
        end = min(l, ii+256*20-2)
        for jj in range(ii, end, 20):
            d = rda(p, handle['transfer']).data
            if (end-jj-len(d)) in (-1, 0):
                d += rda(p, handle['transfer']).data # tack on CRC16 straggler byte(s)

            outf.write( d[ : min(end-jj,20) ] )
            checker.update(d)

            if debug>1:
                print "%04x: %s %s" % (jj, hexlify(d), repr(d))

        # check CRC16 and ack
        if checker.digest()!=0:
            raise AssertionError, checker.hexdigest()
        checker.reset()
        counter += 1
        p.wr(handle['check'], struct.pack('<L', counter), False)
        if debug:
            print "%d: read %d/%d bytes so far (%d/sec)" % (counter, end, l, end // (time.time()-startat))

    rda(p, handle['cmd_status'], idata=0)
    return end

def tt_write_file(p, fileno, buf, expect_end=True, debug=False):
    # strange ordering: file 0x001234ab (ttwatch naming) becomes 0012ab34
    assert (fileno>>24)==0
    cmdno = bytearray((0, (fileno>>16)&0xff, fileno&0xff, (fileno>>8)&0xff))

    tt_send_command(p, cmdno)
    l = len(buf)
    p.wr(handle['length'], struct.pack('<L', len(buf)))     # 0x28 = length in/out

    counter = 0
    startat = time.time()
    checker = tt_crc16_streamer()
    for ii in range(0, l, 256*20-2):
        # write up to 256*20-2 data bytes in 20B chunks
        end = min(l, ii+256*20-2)
        for jj in range(ii, end, 20):
            out = buf[jj : min(jj+20, end)]
            checker.update(out)

            if jj+20>=end:
                out += struct.pack('<H', checker.digest())
            p.wr(handle['transfer'], out[:20])
            if len(out)>20: p.wr(handle['transfer'], out[20:])

            if debug>1:
                print "%04x: %s %s" % (jj, hexlify(out), repr(out))

        # check CRC16 and ack
        checker.reset()
        counter += 1
        if end<l or expect_end:
            rda(p, 0x2e, idata=counter, timeout=20)
        if debug:
            print "%d: wrote %d/%d bytes so far (%d/sec)" % (counter, end, l, end // (time.time()-startat))

    rda(p, handle['cmd_status'], idata=0)
    return end

def tt_list_sub_files(p, fileno):
    # strange ordering: file 0x001234ab (ttwatch naming) becomes 0012ab34
    assert (fileno>>24)==0
    cmdno = bytearray((3, (fileno>>16)&0xff, fileno&0xff, (fileno>>8)&0xff))

    tt_send_command(p, cmdno)
    buf = bytearray()
    while True:
        h, d, id = rda(p)
        if h==handle['transfer']: buf.extend(d)
        elif h==handle['cmd_status'] and id==0: break
        else: raise AssertionError, ("0x%02x"%h,d,id)

    # first uint16 is length, subsequent are file numbers offset from base
    subfiles = struct.unpack('<%dH'%(len(buf)/2), buf)
    assert subfiles[0]+1==len(subfiles)
    return tuple((fileno&0x00ff0000)+sf for sf in subfiles[1:])

def tt_delete_file(p, fileno):
    # strange ordering: file 0x001234ab (ttwatch naming) becomes 0012ab34
    assert (fileno>>24)==0
    cmdno = bytearray((4, (fileno>>16)&0xff, fileno&0xff, (fileno>>8)&0xff))

    tt_send_command(p, cmdno)
    buf = bytearray()
    while True:
        h, d, id = rda(p, timeout=20)
        if h==handle['transfer']: buf.extend(d)
        elif h==handle['cmd_status'] and id==0: break
        else: raise AssertionError, (hnone(h),d,hnone(id))

    return buf

########################################

if len(sys.argv)!=3:
    print '''Need two arguments:
          ttblue.py <bluetooth-address> <pairing-code>
    OR    ttblue.py <bluetooth-address> pair

    Where bluetooth-address is the twelve-digit address
    of your TomTom GPS (E4:04:39:__:__:__) and
    pairing-code is either the previously established
    code used to pair a phone, or the string "pair"
    to create a new pairing.'''
    raise SystemExit

def setup(addr):
    p = None
    while p is None:
        try:
            p=btle.Peripheral(addr, btle.ADDR_TYPE_PUBLIC)
        except btle.BTLEException as e:
            print e
            time.sleep(1)
    d = MyDelegate()
    p.setDelegate(d)
    p.wr = p.writeCharacteristic
    return p

p = setup(sys.argv[1])

try:
    # magic initialization/authentication sequence...
    # codes that are listed in file 0x0002000F should work

    if sys.argv[2]=="pair":
        code = int(raw_input("Code? "))
        newpair = True
    else:
        code = int(sys.argv[2])
        newpair = False
    code = struct.pack('<L', code)
    if 0:
        p.wr(0x33, '\x01\0')
        p.wr(0x26, '\x01\0')
        p.wr(0x2f, '\x01\0')
        p.wr(0x29, '\x01\0')
        p.wr(0x2c, '\x01\0')
    if 1:
        p.wr(0x83, '\x01\0')
        p.wr(0x88, '\x01\0')
        p.wr(0x73, '\x01\0')
        p.wr(0x7c, '\x01\0')
        p.wr(0x76, '\x01\0')
        p.wr(0x79, '\x01\0')

    p.wr(handle['magic'], magic_bytes)
    p.wr(handle['passcode'], '\x01\0')
    response = rda(p, handle['passcode']).idata

    if response == 1:
        print "Paired using code %s." % hexlify(code)
    else:
       raise RuntimeError, "Failed to pair with provided code"


    if 1:
        tt_delete_file(p, file['hostname'])
        tt_write_file(p, file['hostname'], 'Syncing…')

    if 1:
        print "Reading XML preferences (file file['preference']) ..."
        with open('preferences.xml', 'wb') as f:
            tt_read_file(p, file['preference'], f)
            print "Got %d bytes" % f.tell()

    if 1:
        print "Checking activity file status..."
        files = tt_list_sub_files(p, file['activity_start'])
        print "Got %d activities: %s" % (len(files), files)

        filetime = datetime.now().strftime("%Y%m%d_%H%M%S")
        for ii,fileno in enumerate(files):
            tt_delete_file(p, file['hostname'])
            tt_write_file(p, file['hostname'], 'Activity %d/%d…' % (ii+1, len(files)))

            print "Saving activity file 0x%08x.ttbin..." % fileno
            with open('%08x_%s.ttbin' % ( fileno, filetime), 'wb') as f:
                tt_read_file(p, fileno, f, debug=True)
                print "  got %d bytes." % f.tell()
            print "  saved to %s" % f.name

            tt_delete_file(p, file['hostname'])
            tt_write_file(p, file['hostname'], '%d/%d synced.' % (ii+1, len(files)))

            print "Deleting activity file 0x%08x..." % fileno
            print tt_delete_file(p, fileno)

    if 1:
        gqf = requests.get('https://gpsquickfix.services.tomtom.com/fitness/sifgps.f2p3enc.ee?timestamp=%d' % time.time()).content
        print "Sending QuickGPSFix update (%d bytes)..." % len(gqf)
        tt_delete_file(p, file['hostname'])
        tt_write_file(p, file['hostname'], 'GPSQuickFix…')
        tt_delete_file(p, file['quickgps'])
        tt_write_file(p, file['quickgps'], gqf, debug=True, expect_end=True)

        p.wr(handle['cmd_status'], bytearray((0x05, 0x01, 0x00, 0x01))) # magic?
#        p.disconnect()

    if 1:
        tt_delete_file(p, file['hostname'])
        tt_write_file(p, file['hostname'], 'ttblue, yo!')
except KeyboardInterrupt:
    pass
finally:
    p.disconnect()
