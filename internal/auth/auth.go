// Package auth manages the optional ghostshell playback password.
// The password hash is stored in /etc/ghostshell/.playback_passwd (root:root 0600).
// When the file exists all `ghostshell play` invocations prompt for the password.
package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// PasswdFile is the path to the bcrypt hash file. It is a var (not a const) so
// tests can redirect it to a temp location; in production it keeps this default.
var PasswdFile = "/etc/ghostshell/.playback_passwd"

// bcryptCost is the work factor used when hashing new passwords.
const bcryptCost = 12

// MaxAttempts is the number of wrong-password tries before PromptAndVerify fails.
const MaxAttempts = 3

// ErrIncorrectPassword is returned by Verify when the supplied password does not
// match the stored hash. It is a stable sentinel so callers can distinguish a
// wrong password from an I/O error without depending on bcrypt's internals.
var ErrIncorrectPassword = errors.New("incorrect password")

// IsSet reports whether a playback password has been configured.
func IsSet() bool {
	_, err := os.Stat(PasswdFile)
	return err == nil
}

// SetPassword hashes password with bcrypt and writes it to PasswdFile with mode
// 0600 under a 0700 directory. If the directory or file already exists with
// looser permissions, they are tightened so the on-disk state always matches the
// documented root:root 0600 / 0700 modes.
func SetPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	dir := filepath.Dir(PasswdFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}
	// MkdirAll leaves a pre-existing directory's mode untouched; enforce 0700.
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("chmod dir: %w", err)
	}
	if err := os.WriteFile(PasswdFile, hash, 0600); err != nil {
		return fmt.Errorf("write passwd: %w", err)
	}
	// WriteFile does not change the mode of a pre-existing file; enforce 0600.
	if err := os.Chmod(PasswdFile, 0600); err != nil {
		return fmt.Errorf("chmod passwd: %w", err)
	}
	return nil
}

// Verify checks password against the stored hash. It returns nil on a match,
// ErrIncorrectPassword on a wrong password, and a distinctly wrapped error on an
// I/O failure reading the hash file.
func Verify(password string) error {
	hash, err := os.ReadFile(PasswdFile)
	if err != nil {
		return fmt.Errorf("read passwd: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrIncorrectPassword
		}
		return fmt.Errorf("compare passwd: %w", err)
	}
	return nil
}

// Remove deletes the password file, disabling playback protection.
func Remove() error {
	err := os.Remove(PasswdFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// PromptAndVerify prompts for the playback password (no echo) up to MaxAttempts
// times. Returns nil if correct or if no password is set. Returns an error after
// MaxAttempts failures.
func PromptAndVerify() error {
	if !IsSet() {
		return nil
	}
	for i := 0; i < MaxAttempts; i++ {
		pw, err := ReadPassword("Playback password: ")
		if err != nil {
			return err
		}
		if err := Verify(pw); err == nil {
			return nil
		}
		if i < MaxAttempts-1 {
			fmt.Fprintln(os.Stderr, "ghostshell: incorrect password, try again")
		}
	}
	return errors.New("incorrect playback password")
}

// ReadPassword reads a password from the terminal without echo.
func ReadPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(pw), "\r\n"), nil
}
