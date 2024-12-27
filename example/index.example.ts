import { generateTotp } from "../src";

const secret = "my_VeRY-secret_str!ng";
const totp = generateTotp(secret);

console.log(`Your One Time Password: [${totp}]`);
