// Raw RFCOMM bridge for a previously paired, explicitly selected device.
// stdout is binary protocol traffic; diagnostics go to stderr.
#import <Foundation/Foundation.h>
#import <IOBluetooth/IOBluetooth.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

@interface Bridge : NSObject <IOBluetoothRFCOMMChannelDelegate>
@property BOOL done;
@property BOOL sdpDone;
@property IOReturn sdpStatus;
@property IOBluetoothRFCOMMChannel *channel;
@end

@implementation Bridge
- (void)sdpQueryComplete:(IOBluetoothDevice *)device status:(IOReturn)status {
    self.sdpStatus = status;
    self.sdpDone = YES;
}
- (void)rfcommChannelData:(IOBluetoothRFCOMMChannel *)channel data:(void *)data length:(size_t)length {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(STDOUT_FILENO, (char *)data + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { self.done = YES; return; }
        offset += count;
    }
}
- (void)rfcommChannelClosed:(IOBluetoothRFCOMMChannel *)channel {
    fprintf(stderr, "RFCOMM channel closed\n");
    self.done = YES;
}
@end

static void tick(void) {
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc == 2 && strcmp(argv[1], "--controller") == 0) {
            NSString *address = [[IOBluetoothHostController defaultController] addressAsString];
            if (!address) { fprintf(stderr, "Bluetooth controller unavailable\n"); return 2; }
            puts(address.UTF8String);
            return 0;
        }
        if (argc == 2 && strcmp(argv[1], "--list") == 0) {
            NSMutableArray *result = [NSMutableArray array];
            for (IOBluetoothDevice *device in [IOBluetoothDevice pairedDevices]) {
                [result addObject:@{@"name": device.name ?: @"", @"address": device.addressString ?: @""}];
            }
            NSData *json = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
            fwrite(json.bytes, 1, json.length, stdout);
            putchar('\n');
            return 0;
        }
        if (argc != 2) { fprintf(stderr, "usage: bluetooth-bridge DEVICE-MAC | --list\n"); return 2; }
        IOBluetoothDevice *device = [IOBluetoothDevice deviceWithAddressString:@(argv[1])];
        if (!device || !device.isPaired) {
            fprintf(stderr, "Pair the selected iPhone in macOS Bluetooth settings first\n");
            return 2;
        }
        Bridge *bridge = [Bridge new];
        // Apple's accessory-to-phone iAP2 service; obtain its current channel via SDP.
        const uint8_t uuidBytes[16] = {0,0,0,0,0xde,0xca,0xfa,0xde,0xde,0xca,0xde,0xaf,0xde,0xca,0xca,0xfe};
        IOBluetoothSDPUUID *uuid = [IOBluetoothSDPUUID uuidWithBytes:uuidBytes length:16];
        IOBluetoothSDPServiceRecord *record = [device getServiceRecordForUUID:uuid];
        IOReturn status = kIOReturnSuccess;
        if (!record) {
            status = [device performSDPQuery:bridge uuids:@[uuid]];
            NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:15];
            while (status == kIOReturnSuccess && !bridge.sdpDone && deadline.timeIntervalSinceNow > 0) tick();
            if (!bridge.sdpDone || bridge.sdpStatus != kIOReturnSuccess) {
                fprintf(stderr, "SDP query failed: start=0x%08x completion=0x%08x received=%d\n", status, bridge.sdpStatus, bridge.sdpDone);
                return 3;
            }
            record = [device getServiceRecordForUUID:uuid];
        }
        BluetoothRFCOMMChannelID channelID = 0;
        if (!record || [record getRFCOMMChannelID:&channelID] != kIOReturnSuccess) {
            fprintf(stderr, "Paired device does not advertise the iAP2 RFCOMM service\n"); return 3;
        }
        IOBluetoothRFCOMMChannel *channel = nil;
        status = [device openRFCOMMChannelSync:&channel withChannelID:channelID delegate:bridge];
        if (status != kIOReturnSuccess) { fprintf(stderr, "RFCOMM open failed: %d\n", status); return 4; }
        bridge.channel = channel;
        fprintf(stderr, "RFCOMM connected, channel=%u\n", channelID);
        int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
        uint8_t input[4096];
        int result = 0;
        while (!bridge.done) {
            tick();
            ssize_t size = read(STDIN_FILENO, input, sizeof(input));
            if (size == 0) break;
            if (size < 0) {
                if (errno == EAGAIN || errno == EINTR) continue;
                result = 5; break;
            }
            size_t mtu = MAX(1, channel.getMTU);
            for (size_t offset = 0; offset < size; offset += mtu) {
                UInt16 count = (UInt16)MIN(mtu, size - offset);
                if ([channel writeSync:input + offset length:count] != kIOReturnSuccess) {
                    result = 5; bridge.done = YES; break;
                }
            }
        }
        fcntl(STDIN_FILENO, F_SETFL, flags);
        [channel closeChannel];
        return result;
    }
}
