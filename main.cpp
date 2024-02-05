
#include <pcap.h>
#pragma comment (lib, "Packet.lib")
#pragma comment (lib, "wpcap.lib")

#include <tchar.h>
#include <iostream>

BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %lu", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %lu", GetLastError());
        return FALSE;
    }
    return TRUE;
}

std::string getDeviceNameFromUser()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* device;

    pcap_if_t* alldevs = nullptr;
    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return "";
    }

    size_t interfaceIndex = 0;
    for (device=alldevs; device; device=device->next) {
        printf("%llu. %s", ++interfaceIndex, device->name);
        if (device->description) {
            printf(" (%s)\n", device->description);
        } else {
            printf(" (No description available)\n");
        }
    }
    size_t interfaceCount = interfaceIndex;

    if (interfaceCount == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return "";
    }

    printf("Enter the interface number to capture from (1-%llu): ", interfaceCount);
    scanf("%d", &interfaceIndex);

    if (interfaceIndex < 1 || interfaceIndex > interfaceCount)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return "";
    }

    size_t i = 0;
    for (device=alldevs; i<interfaceIndex-1 ;device=device->next, i++) {}
    std::string ret = device->name;
    pcap_freealldevs(alldevs);
    return ret;
}

struct RawSocket
{
    pcap_t* handle{};
    int8_t Open(const char* deviceName)
    {
        char errbuf[PCAP_ERRBUF_SIZE];

        if (LoadNpcapDlls() == 0)
            return -3;
        handle = pcap_open_live(deviceName, 65535, 1, 1, errbuf);
        if (handle == nullptr)
            return -4;

        return 0;
    }

    RawSocket()
    {
        ZeroMemory(this, sizeof(RawSocket));
    }

    ~RawSocket()
    {
        ZeroMemory(this, sizeof(RawSocket));
    }
};

bool writeWavFile(char* baseFileName, FILE* outFile[], size_t channel)
{
    if (outFile[channel] == nullptr) {
        char fname[64] = {};
        sprintf(fname, "%s_%02llu.wav", baseFileName, channel);
        outFile[channel] = fopen(fname, "wb+");
        if (!outFile[channel]) {
            printf("Failed to open output file '%s': %d\n", fname, errno);
            return false;
        }
        uint32_t temp32 = 0;
        uint32_t temp16 = 0;

        fwrite(std::string("RIFF").c_str(), 1, 4, outFile[channel]);
        temp32 = 36;
        fwrite(&temp32, 1, 4, outFile[channel]);
        fwrite(std::string("WAVE").c_str(), 1, 4, outFile[channel]);

        fwrite(std::string("fmt ").c_str(), 1, 4, outFile[channel]);
        temp32 = 16;
        fwrite(&temp32, 1, 4, outFile[channel]);
        temp16 = 1;
        fwrite(&temp16, 1, 2, outFile[channel]);
        temp16 = 1;
        fwrite(&temp16, 1, 2, outFile[channel]);
        temp32 = 48000;
        fwrite(&temp32, 1, 4, outFile[channel]);
        temp32 = 48000 * 1 * 3;
        fwrite(&temp32, 1, 4, outFile[channel]);
        temp16 = 1 * 3;
        fwrite(&temp16, 1, 2, outFile[channel]);
        temp16 = 24;
        fwrite(&temp16, 1, 2, outFile[channel]);

        fwrite(std::string("data").c_str(), 1, 4, outFile[channel]);
        temp32 = 16;
        temp32 = 0;
        fwrite(&temp32, 1, 4, outFile[channel]);
    }
    return true;
}

uint32_t convertEthToPCM(uint32_t src)
{
    src = (src & 0xff0000) >> 16 | (src & 0x00ff00) | (src & 0x0000ff) << 16;
    src = (src & 0xf0f0f0) >>  4 | (src & 0x0f0f0f) <<  4;

    return src;
}

constexpr size_t channelBufferSize = 3 * 256;
constexpr size_t bufferCount = 64;
constexpr size_t channelDataSize = 3;

bool ctrlAbort = false;

FILE* outFiles[bufferCount];
uint8_t* buffers[bufferCount];
uint32_t channelBuffersOffset[bufferCount] = {};
uint32_t channelTotalSize[bufferCount] = {};
char baseFileName[16];

BOOL WINAPI AbortHandler(DWORD ctrlType)
{
    ctrlAbort = true;
    return 1;
}

void handlePacket(const pcap_pkthdr* header, const u_char* data)
{
    if (header->caplen != 235 && header->caplen != 239) return;

    bool vlan = header->caplen == 239;
    size_t offset = vlan ? 18 : 14;

    for (size_t channel = 0; channel < 64; channel++)
    {
        writeWavFile(baseFileName, outFiles, channel);
        if (channelBuffersOffset[channel] + channelDataSize > channelBufferSize) {
            fwrite(buffers[channel], 1, channelBuffersOffset[channel], outFiles[channel]);
            channelBuffersOffset[channel] = 0;
        }
        uint32_t srcSample = *(uint32_t*) (data + offset);
        uint32_t dstSample = convertEthToPCM(srcSample);

        memcpy(buffers[channel] + channelBuffersOffset[channel], &dstSample, 3);
        channelBuffersOffset[channel] += channelDataSize;
        channelTotalSize[channel] += channelDataSize;
        offset += channelDataSize;
    }
}

int main()
{
    printf("Provide base filename: ");
    scanf("%16s", baseFileName);

    //OPEN SOCKET
    std::string deviceName = getDeviceNameFromUser();
    if (deviceName.empty()) {
        return -1;
    }

    RawSocket sc;
    sc.Open(deviceName.c_str());

    //PROCESS AND NPCAP SETTINGS
    pcap_setbuff(sc.handle, 1024*1024*20);
    pcap_setmintocopy(sc.handle, 1024*1024*5);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    SetConsoleCtrlHandler(AbortHandler, TRUE);

    //INIT CHANNEL BUFFERS
    for (auto & buffer : buffers)
    {
        buffer = static_cast<uint8_t*>(calloc(1, channelBufferSize));
    }

    pcap_pkthdr* header;
    const u_char* data;
    int res;
    while ((res = pcap_next_ex(sc.handle, &header, &data)) >= 0 && !ctrlAbort)
    {
        if (res == 0) continue;
        handlePacket(header, data);
    }

    for (size_t i=0; i<bufferCount; i++) {
        if (outFiles[i] != nullptr) {
            fwrite(buffers[i], 1, channelBuffersOffset[i], outFiles[i]);
        }
    }

    //fclose(inFile);
    //inFile = NULL;
    pcap_close(sc.handle);
    for (size_t x=0; x<bufferCount; x++) {
        if (outFiles[x] != nullptr) {
            uint32_t temp32 = 0;
            fseek(outFiles[x], 4, SEEK_SET);
            temp32 = 36 + channelTotalSize[x];
            fwrite(&temp32, 1, 4, outFiles[x]);
            fseek(outFiles[x], 40, SEEK_SET);
            temp32 = channelTotalSize[x];
            fwrite(&temp32, 1, 4, outFiles[x]);
            fclose(outFiles[x]);
            outFiles[x] = nullptr;
        }
    }
    for (auto & buffer : buffers) {
        free(buffer);
    }

    return 0;
}

