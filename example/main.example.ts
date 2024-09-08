import { generateTOTP } from "../src/main";

const secret = "my_VeRY-secret_str!ng";
const totp = generateTOTP(secret);

console.log(`Your One Time Password: [${totp}]`);