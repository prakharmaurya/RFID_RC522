RFID to read and write string data through index only

1. upload the code microcontroller
2. open serial
3. put card
4. it will show all data in based on default A and B key
5. it will ask for cmd but you have to provide an index where you want to write data 0 to 44 (It will not write any data to sector 0 =>(block 0 - 3) and in all other 14 sectors it will also not write data to trailing blocks )
6. then it will ask for 16 byte data enter that
7. after successfull write it will ask for cmd 0 => to STOP and 1 => to write again on same card

Hope this is useful
