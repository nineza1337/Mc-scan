# McScan - เครื่องมือสแกน Minecraft ความเร็วสูง

McScan เป็นเครื่องมือสำหรับค้นหาและตรวจสอบสถานะของเซิร์ฟเวอร์ Minecraft ที่เปิดให้บริการอยู่ในระบบเครือข่าย โปรเจกต์นี้ถูกออกแบบมาเพื่อประสิทธิภาพสูงสุด โดยมีการนำ AF_XDP มาใช้งาน
**AF_XDP** และ **Raw Sockets** มาใช้งานในเวอร์ชันภาษา C และยังมีความยืดหยุ่นด้วยเวอร์ชันภาษา Go สำหรับการใช้งานทั่วไป

## คุณสมบัติเด่น (Features)
*   **ความเร็วสูง (High Performance):** ใช้เทคนิคการส่งแพ็กเก็ตแบบ Raw และ AF_XDP ในการค้นหาเซิร์ฟเวอร์ (ในเวอร์ชัน C)
*   **ข้อมูลครบถ้วน:** สามารถดึงข้อมูล Version, จำนวนผู้เล่น (Online/Max), และข้อความต้อนรับ (MOTD/Description)
*   **รองรับเป้าหมายจำนวนมาก:** สามารถสแกนช่วง IP แบบ CIDR (เช่น 192.168.1.0/24) หรือโหลดรายการ IP จากไฟล์ได้
*   **Multi-threading:** ทำงานแบบขนานเพื่อความรวดเร็วในการตรวจสอบข้อมูล

## การติดตั้งและคอมไพล์ (Installation & Build)

### 1. เวอร์ชัน C (Linux Only - ประสิทธิภาพสูงสุด)
เวอร์ชันนี้ต้องการ Linux Kernel ที่รองรับ XDP และ BPF

**สิ่งที่ต้องมี (Requirements):**
*   GCC หรือ Clang
*   libxdp-dev
*   libbpf-dev

**คำสั่ง Compile:**
```bash
gcc scan.c -o scan -lxdp -lbpf -lpthread
```
*หากต้องการใช้ AF_XDP เต็มรูปแบบ ต้องคอมไพล์ BPF Kernel Program แยกต่างหาก (ขึ้นอยู่กับการตั้งค่า)*

### 2. เวอร์ชัน Go (Cross-Platform / ใช้งานง่าย)
เวอร์ชันนี้สามารถรันได้ง่ายและมีการจัดการ Thread ที่ดี

**คำสั่ง Build:**
```bash
go build scan.go
```

## วิธีใช้งาน (Usage)

### สำหรับเวอร์ชัน C (Recommeded)

รูปแบบคำสั่ง (Command Format):
```bash
sudo ./scan <Interface> <Target_File> <Unused> <Gateway_MAC> <Output_File> <PPS> -p <Start_Port>-<End_Port> <Source_IP>
```

**ตัวอย่างการใช้งาน (Example):**
```bash
sudo ./scan ens160 cidrip-list.txt 0 ff:ff:ff:ff:ff:ff th.txt 5000000 -p 25565-65580 192.168.1.1
```

**คำอธิบายพารามิเตอร์ (Parameters):**
*   **Interface**: ชื่อ Network Interface ที่จะใช้ส่งข้อมูล (เช่น `ens160`, `eth0`)
*   **Target_File**: ไฟล์ที่มีรายชื่อ IP หรือ CIDR ที่ต้องการสแกน
*   **Unused**: ค่าที่สำรองไว้ (ใส่ `0`)
*   **Gateway_MAC**: MAC Address ของ Gateway หรือ Router ที่ออกเน็ต (จำเป็นสำหรับ Raw Socket)
*   **Output_File**: ชื่อไฟล์สำหรับบันทึกผลลัพธ์
*   **PPS**: อัตราการส่งแพ็กเก็ตต่อวินาที (Packets Per Second)
*   **-p Start-End**: ช่วงพอร์ตที่ต้องการสแกน
*   **Source_IP**: IP ของเครื่องเราที่ใช้สแกน (ใส่ไว้ท้ายสุด)

---

### สำหรับเวอร์ชัน Go (Alternative)
```bash
./scan <CIDR> -p 25565-25565 -o output.txt -t 5000
```

---

## License

This software is provided for educational and personal use only.

**Permitted Rights:**
1.  **Use**: You are free to use this software for private, educational, or internal business purposes.
2.  **Modification**: You are free to modify the source code to suit your needs.
3.  **Distribution**: You may distribute the original or modified source code, provided it is done free of charge and typically for educational or open-source contribution purposes.

**Restrictions:**
1.  **No Resale**: You are **STRICTLY PROHIBITED** from selling, licensing, or otherwise monetizing this software, its source code, or any modified versions of it. This includes selling compiled binaries or including this software as part of a paid product or service.
2.  **No Warranty**: This software is provided "as is" without warranty of any kind.

By using or modifying this software, you agree to these terms.
