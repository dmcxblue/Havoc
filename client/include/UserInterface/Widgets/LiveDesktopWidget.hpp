#ifndef HAVOC_LIVEDESKTOPWIDGET_HPP
#define HAVOC_LIVEDESKTOPWIDGET_HPP

#include <QWidget>
#include <QGridLayout>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <QString>
#include <QTcpServer>
#include <QTcpSocket>
#include <QImage>
#include <QTimer>
#include <QMutex>
#include <QByteArray>
#include <QScrollArea>

namespace HavocNamespace::UserInterface::Widgets
{
    class LiveDesktopWidget : public QObject
    {
        Q_OBJECT

    public:
        QWidget*     LiveDesktopTabWidget = nullptr;
        QString      SessionID;

        void setupUi( QWidget* Form );

    private:
        // -- connection panel --
        QGridLayout* gridLayout            = nullptr;
        QGroupBox*   groupConnection       = nullptr;

        QLabel*      labelServer           = nullptr;
        QLabel*      labelPort             = nullptr;
        QLabel*      labelPipe             = nullptr;

        QComboBox*   comboServer           = nullptr;
        QLineEdit*   editPort             = nullptr;
        QLineEdit*   editPipe             = nullptr;

        QPushButton* buttonStart           = nullptr;
        QPushButton* buttonRegenerate      = nullptr;

        // -- viewer area --
        QLabel*      labelView             = nullptr;
        QScrollArea* scrollArea            = nullptr;
        QLabel*      statusLabel           = nullptr;

        // -- networking --
        QTcpServer*  tcpServer             = nullptr;
        QTcpSocket*  deskSocket            = nullptr;
        QTcpSocket*  inputSocket           = nullptr;

        // -- frame state --
        QByteArray   pixBuf;
        int          frameW  = 0;
        int          frameH  = 0;
        int          screenW = 0;
        int          screenH = 0;
        int          frameCount = 0;
        int          lastDecompSize = 0;
        int          lastExpectedSize = 0;
        QMutex       frameMutex;
        bool         frameDirty = false;

        // -- protocol read state --
        enum ReadState {
            WaitMagic,
            WaitConnType,
            WaitFrameFlag,
            WaitFrameHeader,
            WaitFrameData
        };
        ReadState    readState = WaitMagic;
        QByteArray   readBuf;
        int          pendingCompressedSize = 0;
        int          pendingFW = 0;
        int          pendingFH = 0;

        // -- render timer --
        QTimer*      renderTimer = nullptr;

        void dispatch( const QString& command );
        void regenerateNames();
        void populateServerHosts();
        void sendInt( QTcpSocket* s, qint32 v );
        void requestFrame();

        static QByteArray lznt1Decompress( const QByteArray& src );
        static void mergePixelDiff( QByteArray& dst, const QByteArray& src, int size );

    private slots:
        void onStartClicked();
        void onRegenerateClicked();
        void onNewConnection();
        void onDeskReadyRead();
        void onDeskDisconnected();
        void onRenderTick();
    };
}

#endif
