// Package secure agrupa utilidades de higiene de memoria para datos sensibles.
package secure

// Wipe sobrescribe el buffer con ceros.
//
// Se usa sobre el plaintext descifrado (DNI y contraseña) apenas deja de
// necesitarse, para acotar la ventana en la que el dato en claro es visible en
// un core dump o en memoria swapeada.
//
// Limitación conocida: en Go solo se pueden limpiar []byte. Los string son
// inmutables y sus bytes quedan a merced del GC, así que el dato en claro se
// mantiene en []byte todo lo que el flujo permite.
func Wipe(b []byte) {
	clear(b)
}
