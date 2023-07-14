import { webcrypto } from 'one-webcrypto';
import * as uint8arrays from 'uint8arrays';
import errors from './errors';
import { CharSize, EccCurve, Msg } from './types';
import { DEFAULT_SALT_LENGTH } from './constants';

/* Cryto */

// Generate a public exponent
export function publicExponent(): Uint8Array {
	return new Uint8Array([0x01, 0x00, 0x01]);
}

export function eccCurveToBitLength(namedCurve: EccCurve): number {
	// Get the integer following 'P-'
	const bitLength = parseInt(namedCurve.slice(2), 10);
	if (isNaN(bitLength) || bitLength % 8 !== 0) {
		throw errors.InvalidEccCurve;
	}
	return bitLength;	
}

// Interpret a Uint8Array as a fingerprint
export function fingerprintFromBuf(buf: Uint8Array): string {
	return Array.from(buf)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join(':');
}


// How we join an iv and cipher into a cipher text
export function joinCipherText(
	ivBuf: ArrayBuffer,
	cipherBuf: ArrayBuffer
): ArrayBuffer {
	const wrapIvBuf = new Uint8Array(ivBuf);
	const wrapCipherBuf = new Uint8Array(cipherBuf);
	const joined = new Uint8Array(
		wrapIvBuf.length + 1 + wrapCipherBuf.length
	);
	joined.set(wrapIvBuf);
	// Set the delimeter at the end of the iv. It's a period (46)
	joined.set([46], wrapIvBuf.length);
	joined.set(wrapCipherBuf, wrapIvBuf.length + 1);
	return joined.buffer;
}

// How we split a cipher text into an iv and cipher
export function splitCipherText(
	cipherText: ArrayBuffer,
	saltLength: number = DEFAULT_SALT_LENGTH
): [ArrayBuffer, ArrayBuffer] {
	const wrapCipherText = new Uint8Array(cipherText);
	// delimeter is a period
	const ivBuf = wrapCipherText.slice(0, saltLength);
	// Check for delimeter -- the DEFAULT_SALT_LENGTH + 1 th byte should be a period (46)
	if (wrapCipherText[saltLength] !== 46) {
		throw errors.InvalidCipherText;
	}

	const cipherBuf = wrapCipherText.slice(saltLength + 1);

	return [ivBuf, cipherBuf];
}

/* Normalize _ to ArrayBuffer */

export const normalizeUtf8ToBuf = (msg: Msg): ArrayBuffer => {
	return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B8));
};

export const normalizeUtf16ToBuf = (msg: Msg): ArrayBuffer => {
	return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B16));
};

export const normalizeBase64ToBuf = (msg: Msg): ArrayBuffer => {
	return normalizeToBuf(msg, base64ToArrBuf);
};

export const normalizeUnicodeToBuf = (msg: Msg, charSize: CharSize) => {
	switch (charSize) {
		case 8:
			return normalizeUtf8ToBuf(msg);
		default:
			return normalizeUtf16ToBuf(msg);
	}
};

/* Array Buffer to _ */

export function arrBufToStr(buf: ArrayBuffer, charSize: CharSize): string {
	const arr = charSize === 8 ? new Uint8Array(buf) : new Uint16Array(buf);
	return Array.from(arr)
		.map((b) => String.fromCharCode(b))
		.join('');
}

export function arrBufToBase64(buf: ArrayBuffer): string {
	return uint8arrays.toString(new Uint8Array(buf), 'base64pad');
}

/* _ to Array Buffer */

export function strToArrBuf(str: string, charSize: CharSize): ArrayBuffer {
	const view =
		charSize === 8 ? new Uint8Array(str.length) : new Uint16Array(str.length);
	for (let i = 0, strLen = str.length; i < strLen; i++) {
		view[i] = str.charCodeAt(i);
	}
	return view.buffer;
}

export function base64ToArrBuf(string: string): ArrayBuffer {
	return uint8arrays.fromString(string, 'base64pad').buffer;
}

/* Misc */

export function randomBuf(
	length: number,
	{ max }: { max: number } = { max: 255 }
): ArrayBuffer {
	if (max < 1 || max > 255) {
		throw errors.InvalidMaxValue;
	}

	const arr = new Uint8Array(length);

	if (max == 255) {
		webcrypto.getRandomValues(arr);
		return arr.buffer;
	}

	let index = 0;
	const interval = max + 1;
	const divisibleMax = Math.floor(256 / interval) * interval;
	const tmp = new Uint8Array(1);

	while (index < arr.length) {
		webcrypto.getRandomValues(tmp);
		if (tmp[0] < divisibleMax) {
			arr[index] = tmp[0] % interval;
			index++;
		}
	}

	return arr.buffer;
}

export function joinBufs(fst: ArrayBuffer, snd: ArrayBuffer): ArrayBuffer {
	const view1 = new Uint8Array(fst);
	const view2 = new Uint8Array(snd);
	const joined = new Uint8Array(view1.length + view2.length);
	joined.set(view1);
	joined.set(view2, view1.length);
	return joined.buffer;
}

export const normalizeToBuf = (
	msg: Msg,
	strConv: (str: string) => ArrayBuffer
): ArrayBuffer => {
	if (typeof msg === 'string') {
		return strConv(msg);
	} else if (typeof msg === 'object' && msg.byteLength !== undefined) {
		// this is the best runtime check I could find for ArrayBuffer/Uint8Array
		const temp = new Uint8Array(msg);
		return temp.buffer;
	} else {
		throw new Error(
			'Improper value. Must be a string, ArrayBuffer, Uint8Array'
		);
	}
};

/* istanbul ignore next */
export async function structuralClone(obj: any) {
	return new Promise((resolve) => {
		const { port1, port2 } = new MessageChannel();
		port2.onmessage = (ev) => resolve(ev.data);
		port1.postMessage(obj);
	});
}

export default {
	joinCipherText,
	fingerprintFromBuf,
	eccCurveToBitLength,
	splitCipherText,
	arrBufToStr,
	arrBufToBase64,
	strToArrBuf,
	base64ToArrBuf,
	publicExponent,
	randomBuf,
	joinBufs,
	normalizeUtf8ToBuf,
	normalizeUtf16ToBuf,
	normalizeBase64ToBuf,
	normalizeToBuf,
	structuralClone,
};
