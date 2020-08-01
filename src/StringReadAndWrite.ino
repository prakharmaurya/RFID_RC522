/* 
 * Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      ESP32         Ardunio  
 *             Reader/PCD                  Uno
 * Signal      Pin          
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          22              9
 * SPI SS      SDA(SS)      21              10
 * SPI MOSI    MOSI         23              11
 * SPI MISO    MISO         19              12
 * SPI SCK     SCK          18              13
 */

#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 9 // Configurable, see typical pin layout above
#define SS_PIN 10 // Configurable, see typical pin layout above
#define arduReset 8

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance

MFRC522::MIFARE_Key key;

bool isNewCard = true;

// String strKey;

/**
 * Initialize.
 */
void setup()
{
    digitalWrite(arduReset, HIGH);
    delay(200);
    pinMode(arduReset, OUTPUT);
    delay(200);
    Serial.begin(9600); // Initialize serial communications with the PC
    while (!Serial)
    { // Do nothing if no serial port is opened
        //(added for Arduinos based on ATMEGA32U4)
    }
    SPI.begin();        // Init SPI bus
    mfrc522.PCD_Init(); // Init MFRC522 card

    // Prepare the key (used both as key A and as key B)
    // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
    for (byte i = 0; i < 6; i++)
    {
        key.keyByte[i] = 0xFF;
    }

    // Getting new A & B for sectors write
    //    Serial.print("Waiting for key less then or equal 6 char...");
    //    while(1){
    //      delay(2000);
    //      if(Serial.available()){
    //        strKey = Serial.readString();
    //        break;
    //      }
    //      Serial.print(".");
    //    }
    //    Serial.println(" ");
    //    Serial.println("Entered key is - "+ strKey);

    // Storing new keys
    //    for(byte i=0; i<strKey.length(); i++){
    //      key.keyByte[i] = strKey[i];
    //    }
    //    Serial.println(F("Got Key"));

    Serial.println(F("Scan a MIFARE Classic PICC to read and write."));
    Serial.print(F("Using key (for A and B):"));
    dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
    Serial.println(F("BEWARE: Data will be written to the PICC, in sector #1"));
}

/**
 * Main loop.
 */
void loop()
{
    // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
    if (!mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if (!mfrc522.PICC_ReadCardSerial())
        return;

    // Show some details of the PICC (that is: the tag/card)
    Serial.print(F("Card UID:"));
    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    Serial.println();
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.println(mfrc522.PICC_GetTypeName(piccType));

    // Check for compatibility
    if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI && piccType != MFRC522::PICC_TYPE_MIFARE_1K && piccType != MFRC522::PICC_TYPE_MIFARE_4K)
    {
        Serial.println(F("This only works with MIFARE Classic cards."));
        return;
    }

    // Authenticate using key A
    Serial.println(F("Authenticating using key A."));
    Serial.println();
    // Reading Data
    for (byte i = 0; i < 45; i++)
    {
        read_data_from_block_addr(mfrc522, i);
    }

    // Get place index to write,
    // get_string_data_from_serial(data);
    // get_int_data_from_serial(index);
    byte index = -1;
    byte block_size = 16;
    byte dataBlock[block_size];
    bool isContinue;
    String data = get_write_cmd_index_data(index, isContinue);
    while (isContinue)
    {
        trim_data(data, dataBlock, block_size);

        // Authenticate using key B
        Serial.println(F("Authenticating again using key B"));
        // Write data to the block
        write_data_to_block_addr(mfrc522, dataBlock, index);

        check_result(dataBlock, index);
        data = get_write_cmd_index_data(index, isContinue);
    }

    // Authenticate using key A
    Serial.println(F("Authenticating using key A."));
    Serial.println();
    // Reading Data
    for (byte i = 0; i < 45; i++)
    {
        read_data_from_block_addr(mfrc522, i);
    }

    Serial.print("/*Halt*/");

    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();
}

void read_data_from_block_addr(MFRC522 &mfrc522, byte index)
{
    Serial.flush();
    // Read data from the block
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);
    byte trailerBlock = get_trailing_block(index);

    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK)
    {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        ResetBoard();
        return;
    }

    byte blockAddr = get_block_addr(index);
    Serial.print(F("/*Block-"));
    Serial.print(blockAddr);
    Serial.print(F(",Data-"));
    status = (MFRC522::StatusCode)mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK)
    {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.print(mfrc522.GetStatusCodeName(status));
        ResetBoard();
        return;
    }
    // dump_byte_array(buffer, 16);
    // Serial.println("String interpretation is :-");
    dump_string_array(buffer, 16);
    Serial.println("*/");
}

void write_data_to_block_addr(MFRC522 &mfrc522, byte *dataBlock, byte index)
{
    // Write data to the block
    MFRC522::StatusCode status;
    byte trailerBlock = get_trailing_block(index);
    Serial.print(F("Trailer block : "));
    Serial.println(trailerBlock);
    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK)
    {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        ResetBoard();
        return;
    }
    byte blockAddr = get_block_addr(index);
    Serial.print(F("Writing data into block "));
    Serial.print(blockAddr);
    Serial.println(F(" ..."));
    // dump_byte_array(dataBlock, 16);
    dump_string_array(dataBlock, 16);
    // Error
    status = (MFRC522::StatusCode)mfrc522.MIFARE_Write(blockAddr, dataBlock, 16);
    if (status != MFRC522::STATUS_OK)
    {
        Serial.print(F("MIFARE_Write() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        ResetBoard();
    }
    Serial.println();
}

void check_result(byte *data, byte index)
{
    delay(1000);
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);
    byte trailerBlock = get_trailing_block(index);

    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK)
    {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        ResetBoard();
        return;
    }

    byte blockAddr = get_block_addr(index);
    status = (MFRC522::StatusCode)mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK)
    {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        ResetBoard();
    }

    Serial.println(F("Checking result..."));
    byte count = 0;

    for (byte i = 0; i < 16; i++)
    {
        // Compare buffer (= what we've read) with dataBlock (= what we've written)
        if (buffer[i] == data[i])
            count++;
    }
    Serial.print(F("Number of bytes that match = "));
    Serial.println(count);
    if (count == 16)
    {
        Serial.println(F("Success"));
    }
    else
    {
        Serial.println(F("Failure, no match :-("));
        Serial.println(F("  perhaps the write didn't work properly..."));
        ResetBoard();
    }
    Serial.println();
}

void get_string_data_from_serial(String &serialData)
{
    // Getting new Data to write from user for write
    Serial.print("Waiting For Data Input...");
    Serial.flush();
    while (1)
    {
        delay(4000);
        if (Serial.available())
        {
            serialData = Serial.readString();
            break;
        }
        Serial.print(".");
    }
    Serial.println();
    Serial.println("Entered data is - " + serialData);
}

String get_write_cmd_index_data(byte &index, bool &isContinue)
{
    String serialData = "";
    get_string_data_from_serial(serialData);
    if (serialData[0] == '0')
    {
        isContinue = false;
        return "";
    }
    else
    {
        isContinue = true;
    }
    index = (10 * (((byte)serialData[1]) - 48) + ((byte)serialData[2] - 48));
    // Serial.println(index);
    if (!(index >= 0 && index < 45))
    {
        Serial.print("Error-IndexError index is - ");
        Serial.println(index);
        isContinue = false;
        ResetBoard();
        return "";
    }
    String data;
    for (byte i = 0; i < (sizeof(serialData) / sizeof(char)); i++)
        if (i > 2)
        {
            data[i - 3] = serialData[i];
        }
    return data;
}

void get_int_data_from_serial(byte &serialData)
{
    // Getting new Data to write from user for write
    Serial.print(F("Waiting For cmd Input..."));
    Serial.flush();
    while (1)
    {
        delay(2000);
        if (Serial.available())
        {
            serialData = Serial.parseInt();
            break;
        }
        Serial.print(F("."));
    }
    Serial.println();
    Serial.print(F("Entered CMD is - "));
    Serial.println(serialData);
}

void trim_data(String &stringData, byte *byteArray, byte &size)
{
    for (byte i = 0; i < size; i++)
    {
        byteArray[i] = 0x00;
    }
    for (byte i = 0; i < stringData.length(); i++)
    {
        if (stringData[i] >= 0x20)
        {
            byteArray[i] = stringData[i];
        }
    }
}

// Max index 44 allowed
byte get_block_addr(byte index)
{
    byte sector = (index + (index / 3) + 4);
    if (sector < 0 || sector > 62)
    {
        Serial.println(F("Entered index is wrong"));
        ResetBoard();
        return 62;
    }
    return sector;
}
byte get_trailing_block(byte index)
{
    byte tBlock = 4 * (index / 3) + 7;
    if (tBlock < 0 || tBlock > 63)
    {
        Serial.println(F("Entered index is wrong"));
        ResetBoard();
        return 63;
    }
    return tBlock;
}

/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void dump_byte_array(byte *buffer, byte bufferSize)
{
    for (byte i = 0; i < bufferSize; i++)
    {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
    Serial.println();
}

void dump_string_array(byte *buffer, byte bufferSize)
{
    for (byte i = 0; i < bufferSize; i++)
    {
        char temp = buffer[i];
        Serial.print(temp);
    }
}

/*********** Ardunio resetter **************/
void ResetBoard()
{
    Serial.print("/*Resetting*/");
    digitalWrite(arduReset, LOW);
}