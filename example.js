const luminus = require('./index');

async function fetchData() {
    const auth = await new luminus.Authentication('nusstu\\e0123456', 'password').getAuth();
    return await luminus.Api._apiGet(auth, '/module');
}

fetchData().then((res) => console.log(JSON.parse(res)));