package sshd

import (
	"net"

	"github.com/gliderlabs/ssh"
	"github.com/pires/go-proxyproto"

	"github.com/eeeeethan2333/koko/pkg/auth"
	"github.com/eeeeethan2333/koko/pkg/config"
	"github.com/eeeeethan2333/koko/pkg/handler"
	"github.com/eeeeethan2333/koko/pkg/logger"
)

var sshServer *ssh.Server

func StartServer() {
	handler.Initial()
	conf := config.GetConf()
	hostKey := HostKey{Value: conf.HostKey, Path: conf.HostKeyFile}
	logger.Debug("Loading host key")
	signer, err := hostKey.Load()
	if err != nil {
		logger.Fatal("Load host key error: ", err)
	}

	addr := net.JoinHostPort(conf.BindHost, conf.SSHPort)
	logger.Infof("Start SSH server at %s", addr)
	sshServer = &ssh.Server{
		Addr:                       addr,
		KeyboardInteractiveHandler: auth.CheckMFA,
		PasswordHandler:            auth.CheckUserPassword,
		PublicKeyHandler:           auth.CheckUserPublicKey,
		NextAuthMethodsHandler:     auth.MFAAuthMethods,
		HostSigners:                []ssh.Signer{signer},
		Handler:                    handler.SessionHandler,
		SubsystemHandlers:          map[string]ssh.SubsystemHandler{},
	}
	// Set sftp handler
	sshServer.SetSubsystemHandler("sftp", handler.SftpHandler)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatal(err)
	}
	proxyListener := &proxyproto.Listener{Listener: ln}
	logger.Fatal(sshServer.Serve(proxyListener))
}

func StopServer() {
	err := sshServer.Close()
	if err != nil {
		logger.Errorf("SSH server close failed: %s", err.Error())
	}
	logger.Info("Close ssh server")
}
