package AuthProto

import (
	"crypto/rc4"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"sync"
)

const PlatformKey = `CwTJZ1PMHQNcjIII8cLffRUSc0HdrtlJv6hpx1SRZcYm5fXoftR5ods95Us+pZ/3F1WLdV67Ijxjww0Svgmuebw=`

type PlatformCrypto struct {
	RC4Key    []byte
	GlobalXOR []byte
	HashKey   []byte
}

var DefaultState = InitCryptoCore(PlatformKey)

func MakeKey() []byte {
	key := make([]byte, 16)
	n, err := rand.Read(key)
	if err != nil {
		log.Fatalf("failed to read new random key: %s", err)
	}
	if n < 16 {
		log.Fatalf("failed to read entire key, only read %d out of %d", n, 16)
	}
	return key
}

func EncryptPacket(data []byte) []byte {

	var PacketOutput []byte

	var CurrKey = MakeKey()

	for i := 0; i < 16; i++ {
		PacketOutput = append(PacketOutput, CurrKey[i]^DefaultState.GlobalXOR[i])
	}

	EncryptedParams := RC4_Action(CurrKey, data)
	PacketOutput = append(PacketOutput, EncryptedParams...)

	hasher := sha1.New()
	hasher.Write(PacketOutput)
	hasher.Write(DefaultState.HashKey)

	PacketOutput = append(PacketOutput, hasher.Sum(nil)...)

	return PacketOutput
}

func DecryptPacketKey(cipherKey []byte) []byte {

	var tmpKey = make([]byte, 16)

	for i := 0; i < 16; i++ {
		tmpKey[i] = cipherKey[i] ^ DefaultState.GlobalXOR[i]
	}

	return tmpKey
}

func DecryptPacket(data []byte) ([]byte, error) {

	PacketKey := DecryptPacketKey(data[:16])

	BuffSize := binary.BigEndian.Uint32(CoreDecrypt(PacketKey, data[16:16+4]))

	if BuffSize != 1024 {
		return nil, fmt.Errorf("Invalid Block Size (Reply packet)")
	}

	var PacketBlocksEnd []int

	BuffSize += 24

	Start := 16

	for Start < len(data) {
		end := GetMinValue(len(data), Start+int(BuffSize)) - 20 // Remove Hash Size

		PacketBlocksEnd = append(PacketBlocksEnd, end)

		Start += int(BuffSize)
	}

	var ClearPacket []byte
	if len(PacketBlocksEnd) == 1 {
		ClearPacket = append(ClearPacket, CoreDecrypt(PacketKey, data[16:PacketBlocksEnd[0]])[4:]...)
	}

	if len(PacketBlocksEnd) == 2 {
		ClearPacket = append(ClearPacket, CoreDecrypt(PacketKey, data[16:PacketBlocksEnd[0]])[4:]...)
		ClearPacket = append(ClearPacket, CoreDecrypt(PacketKey, data[36:PacketBlocksEnd[1]])[PacketBlocksEnd[0]-16:]...)
	}

	return ClearPacket, nil
}

func GetMinValue(x, y int) int {
	if x < y {
		return x
	} else {
		return y
	}
}

func InitCryptoCore(ClientKey string) PlatformCrypto {

	buff, err := base64.StdEncoding.DecodeString(ClientKey)
	if err != nil {
		panic(err)
	}

	//uint8_t m_rc4Key[32];
	//uint8_t m_xorKey[16];
	//uint8_t m_hashKey[16];

	RC4Key := buff[1 : 33]
	xorKey := buff[33 : 49]
	hashKey := buff[49 : 65]

	return PlatformCrypto{
		RC4Key:    RC4Key,
		GlobalXOR: RC4_Action(RC4Key, xorKey),
		HashKey:   RC4_Action(RC4Key, hashKey),
	}
}

func RC4_Action(key, data []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		log.Fatalln(err)
	}

	c.XORKeyStream(data, data)

	return data
}

func CoreDecrypt(key, data []byte) []byte {
	c2, err := rc4.NewCipher(key)
	if err != nil {
		return nil
	}
	src2 := make([]byte, len(data))
	c2.XORKeyStream(src2, data)

	return src2
}
func DecryptUserAgent(ClientUserAgent string) string {

	XORcounter = 0

	buff, err := base64.StdEncoding.DecodeString(ClientUserAgent)
	if err != nil {
		panic(err)
	}

	UserAgentXOR = buff[0:4]

	var decrypted = make([]byte, 0)
	for i := range buff {
		decrypted = append(decrypted, buff[i]^GetXorByte())
	}

	return string(decrypted)
}

const charset = "abcdefghijklmnopqrstuvwxyz"
const Platform = "e=1,t=gta5ifruit,p=pcros,v=11"

func CreateUserAgent() string {

	XORcounter = 0

	var currKey = make([]byte, 0)

	for i := 0; i < 4; i++ {
		currKey = append(currKey, charset[GenNum(0, len(charset))])
	}

	UserAgentXOR = currKey

	var UserAgentBuff []byte

	UserAgentBuff = append(UserAgentBuff, currKey...)

	for i := 0; i < len(Platform); i++ {
		UserAgentBuff = append(UserAgentBuff, Platform[i]^GetXorByte())
	}

	return fmt.Sprintf("ros %s", base64.StdEncoding.EncodeToString(UserAgentBuff))
}

func GenNum(min, max int) int {
	return rand.Intn(max-min) + min
}

var XORcounter = 0
var UserAgentXOR []byte
var Lock sync.Mutex

func GetXorByte() (result byte) {

	Lock.Lock()
	defer Lock.Unlock()
	if XORcounter >= len(UserAgentXOR) {
		XORcounter = 0
	}

	result = UserAgentXOR[XORcounter]
	XORcounter++
	return
}
