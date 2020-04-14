package common

import (
	"crypto/tls"
	"errors"
	"net/smtp"
	"strconv"
)

// Copy from https://golang.org/src/net/smtp/auth.go, removed TLS check
type insecurePlainAuth struct {
	identity, username, password string
	host                         string
}

func (a *insecurePlainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *insecurePlainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// We've already sent everything.
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

func InsecurePlainAuth(identity, username, password, host string) smtp.Auth {
	return &insecurePlainAuth{identity, username, password, host}
}

// SendEmail is used to send email notifications to users and administrators.
func SendEmail(cfg *Configuration, subject, body string, receivers ...string) error {
	hostname := cfg.Email.Host + ":" + strconv.Itoa(cfg.Email.Port)

	var auth smtp.Auth
	if cfg.Email.Username == "" {
		auth = nil
	} else {
		if cfg.Email.TLS {
			// Set up authentication information.
			auth = smtp.PlainAuth(
				"",
				cfg.Email.Username,
				cfg.Email.Password,
				cfg.Email.Host,
			)
		} else {
			// Set up authentication information.
			auth = InsecurePlainAuth(
				"",
				cfg.Email.Username,
				cfg.Email.Password,
				cfg.Email.Host,
			)
		}
	}

	// Connect to the remote SMTP server.
	c, err := smtp.Dial(hostname)
	if err != nil {
		return err
	}
	defer c.Close()

	if cfg.Email.TLS {
		config := &tls.Config{ServerName: cfg.Email.Host, InsecureSkipVerify: true}
		if err = c.StartTLS(config); err != nil {
			return err
		}
	}

	if auth != nil {
		if err = c.Auth(auth); err != nil {
			return err
		}
	}

	// Set the sender and recipient.
	if err = c.Mail(cfg.Email.FromAddress); err != nil {
		return err
	}
	rcpStr := ""
	delimiter := ""
	for _, addr := range receivers {
		rcpStr += delimiter + addr
		delimiter = ", "
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}

	msg := []byte("Subject: " + subject + "\r\n" +
		"From: " + cfg.Email.FromName + "<" + cfg.Email.FromAddress + ">\r\n" +
		"To: " + rcpStr + "\r\n" +
		"Reply-To: " + cfg.Email.FromAddress + "\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"\r\n" +
		body +
		"\r\n")

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = wc.Write(msg); err != nil {
		return err
	}
	if err = wc.Close(); err != nil {
		return err
	}

	// Finish
	if err = c.Quit(); err != nil {
		return err
	}

	return nil
}

const (
	EmailWelcome = "Thank you for creating an account with Bitwarden. You may now log in with your new account.\n\n" +
		"Did you know that Bitwarden is free to sync with all of your devices? Download Bitwarden today on:\n\n" +
		"Desktop\n============\n\n" +
		"Access Bitwarden on Windows, macOS, and Linux desktops with our native desktop application.\n" +
		"https://bitwarden.com/#download\n\n" +
		"Web Browser\n============\n\n" +
		"Integrate Bitwarden directly into your favorite browser. Use our browser extensions for a seamless browsing experience.\n" +
		"https://bitwarden.com/#download-browser\n\n" +
		"Mobile\n============\n\n" +
		"Take Bitwarden on the go with our mobile apps for your phone or tablet device.\n" +
		"https://bitwarden.com/#download-mobile\n\n" +
		"Web\n============\n\n" +
		"Stuck without any of your devices? Using a friend's computer? You can access your Bitwarden vault from any web enabled device by using the web vault.\n" +
		"{WebVaultUrl}/?utm_source=welcome_email&utm_medium=email\n\n\n" +
		"If you have any questions or problems you can get support at: https://github.com/h44z/bitwarden-go\n\nThank you!\nThe Bitwarden-GO Team"
)
