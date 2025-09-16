// tests/test.js (ESM)
import SecureKV from '../lib/index.js';

(async () => {
    await SecureKV.setItem('token', 'abc123', 'pass');
    const v = await SecureKV.getItem('token', 'pass');
    console.log('got', v);
})();
