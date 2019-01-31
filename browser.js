// **************************************************
//                  Client Side

// Parameters
const g_ServerPublicKey = 'VG4lap1sZRUpAYb0sz3SAal56VdMbPNjvaQUh1zTtxA=';
const g_aesKeyLength = 128;  // 128/192/256

// Libraries - ECDH-25519, Base64
var _createClass=function(){function g(h,k){for(var n,l=0;l<k.length;l++)n=k[l],n.enumerable=n.enumerable||!1,n.configurable=!0,'value'in n&&(n.writable=!0),Object.defineProperty(h,n.key,n)}return function(h,k,l){return k&&g(h.prototype,k),l&&g(h,l),h}}();function _classCallCheck(g,h){if(!(g instanceof h))throw new TypeError('Cannot call a class as a function')}var _X25519_ZERO=new Float64Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),_X25519_ONE=new Float64Array([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),_X25519_NINE=new Uint8Array(32),_X25519_121665=new Float64Array([56129,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);_X25519_NINE[0]=9;var X25519=function(){function g(){_classCallCheck(this,g)}return _createClass(g,null,[{key:'getPublic',value:function getPublic(h){if(32!==h.byteLength)throw new Error('Secret wrong length, should be 32 bytes.');var k=new Uint8Array(h);return g._clamp(k),g._scalarMul(k,_X25519_NINE)}},{key:'getSharedKey',value:function getSharedKey(h,k){if(32!==h.byteLength||32!==k.byteLength)throw new Error('Secret key or public key wrong length, should be 32 bytes.');var l=new Uint8Array(h);return g._clamp(l),g._scalarMul(l,k)}},{key:'_add',value:function _add(h,k,l){for(var n=0;16>n;n++)h[n]=0|k[n]+l[n]}},{key:'_sub',value:function _sub(h,k,l){for(var n=0;16>n;n++)h[n]=0|k[n]-l[n]}},{key:'_mul',value:function _mul(h,k,l){var n=0,o=0,s=new Float64Array(31);for(n=0;16>n;n++)for(o=0;16>o;o++)s[n+o]+=k[n]*l[o];for(n=0;15>n;n++)s[n]+=38*s[n+16];g._car25519(s),g._car25519(s),g._copy(h,s)}},{key:'_sqr',value:function _sqr(h,k){g._mul(h,k,k)}},{key:'_scalarMul',value:function _scalarMul(h,k){var l=new Float64Array(80),n=new Float64Array(_X25519_ONE),o=new Float64Array(_X25519_ZERO),s=new Float64Array(_X25519_ZERO),t=new Float64Array(_X25519_ONE),u=new Float64Array(_X25519_ZERO),v=new Float64Array(_X25519_ZERO),w=new Uint8Array(h),x=0;g._unpack(l,k),g._copy(o,l);for(var C=254;0<=C;--C)x=1&w[C>>>3]>>>(7&C),g._sel25519(n,o,x),g._sel25519(s,t,x),g._add(u,n,s),g._sub(n,n,s),g._add(s,o,t),g._sub(o,o,t),g._sqr(t,u),g._sqr(v,n),g._mul(n,s,n),g._mul(s,o,u),g._add(u,n,s),g._sub(n,n,s),g._sqr(o,n),g._sub(s,t,v),g._mul(n,s,_X25519_121665),g._add(n,n,t),g._mul(s,s,n),g._mul(n,t,v),g._mul(t,o,l),g._sqr(o,u),g._sel25519(n,o,x),g._sel25519(s,t,x);for(var C=0;16>C;C++)l[C+16]=n[C],l[C+32]=s[C],l[C+48]=o[C],l[C+64]=t[C];var y=l.subarray(32),A=l.subarray(16);g._inv25519(y,y),g._mul(A,A,y);var B=new Uint8Array(32);return g._pack(B,A),B}},{key:'_inv25519',value:function _inv25519(h,k){var l=new Float64Array(16);g._copy(l,k);for(var n=253;0<=n;n--)g._sqr(l,l),2!==n&&4!==n&&g._mul(l,l,k);g._copy(h,l)}},{key:'_sel25519',value:function _sel25519(h,k,l){for(var n=0,s=0;16>s;s++)n=~(l-1)&(h[s]^k[s]),h[s]^=n,k[s]^=n}},{key:'_car25519',value:function _car25519(h){for(var k=0,l=0;16>l;l++)h[l]+=65536,k=Math.floor(h[l]/65536),h[(l+1)*(15>l?1:0)]+=k-1+37*(k-1)*(15===l?1:0),h[l]-=65536*k}},{key:'_unpack',value:function _unpack(h,k){for(var l=0;16>l;l++)h[l]=k[2*l]+(k[2*l+1]<<8)}},{key:'_pack',value:function _pack(h,k){var l=new Float64Array(16),n=new Float64Array(16),o=0,s=0;g._copy(n,k),g._car25519(n),g._car25519(n),g._car25519(n);for(var t=0;2>t;t++){for(l[0]=n[0]-65517,o=1;15>o;o++)l[o]=n[o]-65535-(1&l[o-1]>>16),l[o-1]&=65535;l[15]=n[15]-32767-(1&l[14]>>16),s=1&l[15]>>16,l[14]&=65535,g._sel25519(n,l,1-s)}for(o=0;16>o;o++)h[2*o]=255&n[o],h[2*o+1]=n[o]>>8}},{key:'_copy',value:function _copy(h,k){for(var l=k.length,n=0;n<l;n++)h[n]=k[n]}},{key:'_clamp',value:function _clamp(h){h[0]&=248,h[31]=64|127&h[31]}}]),g}();
const _keyStr="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",Base64={encode:function(r){var e,t,o,a,n,d,h,C="",c=0;for(r=Base64._utf8_encode(r);c<r.length;)a=(e=r.charCodeAt(c++))>>2,n=(3&e)<<4|(t=r.charCodeAt(c++))>>4,d=(15&t)<<2|(o=r.charCodeAt(c++))>>6,h=63&o,isNaN(t)?d=h=64:isNaN(o)&&(h=64),C=C+_keyStr.charAt(a)+_keyStr.charAt(n)+_keyStr.charAt(d)+_keyStr.charAt(h);return C},decode:function(r){var e,t,o,a,n,d,h="",C=0;for(r=r.replace(/[^A-Za-z0-9\+\/\=]/g,"");C<r.length;)e=_keyStr.indexOf(r.charAt(C++))<<2|(a=_keyStr.indexOf(r.charAt(C++)))>>4,t=(15&a)<<4|(n=_keyStr.indexOf(r.charAt(C++)))>>2,o=(3&n)<<6|(d=_keyStr.indexOf(r.charAt(C++))),h+=String.fromCharCode(e),64!=n&&(h+=String.fromCharCode(t)),64!=d&&(h+=String.fromCharCode(o));return h=Base64._utf8_decode(h)},_utf8_encode:function(r){var e="";r=r.replace(/\r\n/g,"\n");for(var t=0;t<r.length;t++){var o=r.charCodeAt(t);o<128?e+=String.fromCharCode(o):o>127&&o<2048?(e+=String.fromCharCode(o>>6|192),e+=String.fromCharCode(63&o|128)):(e+=String.fromCharCode(o>>12|224),e+=String.fromCharCode(o>>6&63|128),e+=String.fromCharCode(63&o|128))}return e},_utf8_decode:function(r){var e,t,o,a="",n=0;for(e=t=0;n<r.length;)(e=r.charCodeAt(n))<128?(a+=String.fromCharCode(e),n++):e>191&&e<224?(t=r.charCodeAt(n+1),a+=String.fromCharCode((31&e)<<6|63&t),n+=2):(t=r.charCodeAt(n+1),o=r.charCodeAt(n+2),a+=String.fromCharCode((15&e)<<12|(63&t)<<6|63&o),n+=3);return a}};

// Casting
const str2b64 = Base64.encode;
const b64ToStr = Base64.decode;
const b64ToAb = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const ab2b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
const str2ab = s => b64ToAb(str2b64(s));
const ab2str = a => b64ToStr(ab2b64(a));

const servPublicKey = b64ToAb(g_ServerPublicKey);
const ourPrivateKey = window.crypto.getRandomValues(new Uint8Array(32));
const ourPublicKey  = X25519.getPublic(ourPrivateKey);
const aesKeyAb = X25519.getSharedKey(ourPrivateKey, servPublicKey).slice(0, g_aesKeyLength / 8);
const aesKeyB64 = ab2b64(aesKeyAb);
let aesKeyWebCrypto;


// Aes Key to webcrypto format
window.crypto.subtle.importKey(
  "raw"
  , aesKeyAb
  , 'AES-GCM'
  , true                   // whether the key is extractable (i.e. can be used in exportKey)
  , ["encrypt", "decrypt"] // can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
).then(k => {
  aesKeyWebCrypto = k;
});

function postJson(data_json, url) {
  const ivAb = window.crypto.getRandomValues(new Uint8Array(12));

  // Marshall
  const ivB64 = ab2b64(ivAb);
  const data_str_json = JSON.stringify(data_json);
  const data_ab_formatted_str_json = str2ab(data_str_json.length + ' ' + data_str_json);

  // Encrypt and send
  window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivAb, tagLength: g_aesKeyLength },
    aesKeyWebCrypto,
    data_ab_formatted_str_json
  ).then(data_ab_encr_formatted_str_json => {
    // Marshall
    const data_b64_encr_formatted_str_json = ab2b64(data_ab_encr_formatted_str_json);

    // Log
    console.log(data_str_json);           // Unecrypted data
    console.log('url: ' + url); // Url
    
    // Send data
    var request = new XMLHttpRequest();    
    request.open("POST", url);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify({ data: data_b64_encr_formatted_str_json
                                , pubKey: ab2b64(ourPublicKey)
                                , iv: ivB64
                                }));
  });
};
