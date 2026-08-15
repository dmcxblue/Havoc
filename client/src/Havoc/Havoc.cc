#include <Havoc/Havoc.hpp>
#include <Havoc/Connector.hpp>
#include <Havoc/CmdLine.hpp>

#include <QTimer>

HavocSpace::Havoc::Havoc( QMainWindow* w )
{
    w->setVisible( false );

    spdlog::set_pattern( "[%T] [%^%l%$] %v" );
    spdlog::info(
        "Havoc Framework [Version: {}] [CodeName: {}]",
        HavocNamespace::Version,
        HavocNamespace::CodeName
    );

    this->HavocMainWindow = w;
    this->dbManager = new HavocSpace::DBManager( "data/client.db", DBManager::CreateSqlFile );
}

void HavocSpace::Havoc::Init( int argc, char** argv )
{
    auto List      = std::vector<Util::ConnectionInfo>();
    auto Connect   = new HavocNamespace::UserInterface::Dialogs::Connect;
    auto Arguments = cmdline::parser();
    auto Path      = std::string();

    Arguments.add( "debug",  '\0', "debug mode" );
    Arguments.add( "config", '\0', "toml config path" );
    Arguments.parse_check( argc, argv );


    if ( Arguments.exist( "debug" ) ) {
        spdlog::set_level( spdlog::level::debug );
        spdlog::debug( "Debug mode enabled" );
    }

    if ( Arguments.exist( "config" ) ) {
        Path = Arguments.get<std::string>( "config" );

        if ( ! QFile::exists( Path.c_str() ) ) {
            Path = std::string();
        }
    }

    if ( Path.empty() ) {
        Path = "client/config.toml";
    }

    if ( ! QFile::exists( Path.c_str() ) ) {
        Path = "config.toml";

        if ( ! QFile::exists( Path.c_str() ) ) {
            spdlog::error( "couldn't find config file" );
            Exit();
        }
    }

    try
    {
        Config = toml::parse( Path );
        spdlog::info( "loaded config file: {}", Path );

        const auto& font   = toml::find( Config, "font" );
        const auto  family = toml::find<std::string>( font, "family" );
        const auto  size   = toml::find<int>( font, "size" );

        // QTextCodec removed in Qt 6; UTF-8 is default in Qt 5.15+
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
        QTextCodec::setCodecForLocale( QTextCodec::codecForName( "UTF-8" ) );
#endif
        QApplication::setFont( QFont( family.c_str(), size ) );
        QTimer::singleShot( 10, [&]() {
            QApplication::setFont( QFont( family.c_str(), size ) );
        } );
    }
    catch ( const toml::syntax_error& err )
    {
        spdlog::error( "Config syntax error: {}", err.what() );
        Exit();
    }
    catch ( const std::out_of_range& err )
    {
        spdlog::error( "Config missing required key: {}", err.what() );
        spdlog::warn( "Using default font settings" );
        QApplication::setFont( QFont( "Monospace", 10 ) );
    }
    catch ( const std::exception& err )
    {
        spdlog::error( "Config error: {}", err.what() );
        spdlog::warn( "Using default font settings" );
        QApplication::setFont( QFont( "Monospace", 10 ) );
    }

    this->HavocMainWindow->setVisible( false );

    Connect->TeamserverList = dbManager->listTeamservers();
    Connect->passDB( this->dbManager );
    Connect->setupUi( new QDialog );

    HavocX::Teamserver = Connect->StartDialog( false );

    delete Connect;
}

void HavocSpace::Havoc::Start()
{
    this->ClientInitConnect = false;
    this->HavocMainWindow->setVisible( true );
    this->HavocMainWindow->setCentralWidget( this->HavocAppUI.centralwidget );
    this->HavocMainWindow->show();
}

void HavocSpace::Havoc::Exit()
{
    spdlog::critical( "Exit Program" );

    // Disconnect WebSocket before closing to prevent thread issues
    if ( HavocX::Connector != nullptr ) {
        HavocX::Connector->Disconnect();
    }

    // Finalize Python interpreter to cleanup threads
    if ( Py_IsInitialized() ) {
        Py_Finalize();
    }

    // Close main window
    HavocApplication->HavocMainWindow->close();

    // Quit application event loop gracefully instead of calling exit()
    QApplication::quit();
}

Havoc::~Havoc()
{
    delete this->dbManager;
    delete this->HavocMainWindow;
}
