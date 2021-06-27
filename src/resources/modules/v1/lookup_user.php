<?php

    /** @noinspection PhpUnused */
    /** @noinspection PhpIllegalPsrClassPathInspection */

    namespace modules\v1;

    use Exception;
    use Handler\Abstracts\Module;
    use Handler\Handler;
    use Handler\Interfaces\Response;
    use IntellivoidAPI\Objects\AccessRecord;
    use SpamProtection\Abstracts\BlacklistFlag;
    use SpamProtection\Managers\SettingsManager;
    use SpamProtection\Utilities\Hashing;
    use TelegramClientManager\Abstracts\SearchMethods\TelegramClientSearchMethod;
    use TelegramClientManager\Abstracts\TelegramChatType;
    use TelegramClientManager\Exceptions\TelegramClientNotFoundException;
    use TelegramClientManager\TelegramClientManager;

    /**
     * Class lookup_user
     */
    class lookup_user extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = 'lookup_user';

        /**
         * The version of this module
         *
         * @var string
         */
        public $version = '1.0.0.0';

        /**
         * The description of this module
         *
         * @var string
         */
        public $description = "Returns information about the user that's available in the Spam Protection Database";

        /**
         * Optional access record for this module
         *
         * @var AccessRecord
         */
        public $access_record;

        /**
         * The content to give on the response
         *
         * @var string
         */
        private $response_content;

        /**
         * The HTTP response code that will be given to the client
         *
         * @var int
         */
        private $response_code = 200;

        /**
         * @inheritDoc
         */
        public function getContentType(): string
        {
            return 'application/json';
        }

        /**
         * @inheritDoc
         */
        public function getContentLength(): int
        {
            return strlen($this->response_content);
        }

        /**
         * @inheritDoc
         */
        public function getBodyContent(): string
        {
            return $this->response_content;
        }

        /**
         * @inheritDoc
         */
        public function getResponseCode(): int
        {
            return $this->response_code;
        }

        /**
         * @inheritDoc
         */
        public function isFile(): bool
        {
            return false;
        }

        /**
         * @inheritDoc
         */
        public function getFileName(): string
        {
            return "";
        }

        /**
         * @inheritDoc
         * @throws Exception
         */
        public function processRequest()
        {
            $Parameters = Handler::getParameters(true, true);

            if(isset($Parameters["query"]) == false)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 0,
                        "type" => "CLIENT",
                        "message" => "Missing parameter 'query'"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }

            $TelegramClientManager = new TelegramClientManager();
            $EstimatedPrivateID = Hashing::telegramClientPublicID((int)$Parameters["query"], (int)$Parameters["query"]);
            $TargetTelegramClient = null;

            try
            {
                $TargetTelegramClient = $TelegramClientManager->getTelegramClientManager()->getClient(
                    TelegramClientSearchMethod::byPublicId, $EstimatedPrivateID
                );
            }
            catch (TelegramClientNotFoundException $e)
            {
                unset($e);
            }

            try
            {
                if($TargetTelegramClient == null)
                {
                    $TargetTelegramClient = $TelegramClientManager->getTelegramClientManager()->getClient(
                        TelegramClientSearchMethod::byPublicId, $Parameters["query"]
                    );
                }
            }
            catch (TelegramClientNotFoundException $e)
            {
                unset($e);
            }

            try
            {
                if($TargetTelegramClient == null)
                {
                    $TargetTelegramClient = $TelegramClientManager->getTelegramClientManager()->getClient(
                        TelegramClientSearchMethod::byUsername, str_ireplace("@", "", $Parameters["query"])
                    );
                }
            }
            catch (TelegramClientNotFoundException $e)
            {
                unset($e);
            }

            if($TargetTelegramClient == null)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 404,
                    "error" => array(
                        "error_code" => 10,
                        "type" => "CLIENT",
                        "message" => "Unable to resolve the query"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            if($TargetTelegramClient->Chat->Type == TelegramChatType::Private)
            {
                if($TargetTelegramClient->User->IsBot)
                {
                    $TargetTelegramClient->Chat->Type = "bot";
                }
                else
                {
                    $TargetTelegramClient->Chat->Type = "user";
                }
            }



            $ResponsePayload = [
                "success" => true,
                "response_code" => 200,
                "results" => [
                    "private_telegram_id" => $TargetTelegramClient->PublicID,
                    "entity_type" => $TargetTelegramClient->Chat->Type,
                    "attributes" => [
                        "is_blacklisted" => false,
                        "blacklist_flag" => null,
                        "blacklist_reason" => null,
                        "original_private_id" => null,
                        "is_potential_spammer" => false,
                        "is_operator" => false,
                        "is_agent" => false,
                        "is_whitelisted" => false,
                        "intellivoid_accounts_verified" => false,
                        "is_official" => false,
                    ],
                    "language_prediction" => [
                        "language" => null,
                        "probability" => null
                    ],
                    "spam_prediction" => [
                        "ham_prediction" => null,
                        "spam_prediction" => null,
                    ],
                    "last_updated" => $TargetTelegramClient->LastActivityTimestamp,

                ]
            ];

            switch($TargetTelegramClient->Chat->Type)
            {
                case TelegramChatType::Private:
                case "user":
                case "bot":
                    $UserStatus = SettingsManager::getUserStatus($TargetTelegramClient);

                    if($UserStatus->LargeLanguageGeneralizedID !== null)
                    {
                        $ResponsePayload["results"]["language_prediction"]["language"] = $UserStatus->GeneralizedLanguage;
                        $ResponsePayload["results"]["language_prediction"]["probability"] = $UserStatus->GeneralizedLanguageProbability;
                    }

                    if($UserStatus->GeneralizedID !== "None" && $UserStatus->GeneralizedID !== null)
                    {
                        $ResponsePayload["results"]["spam_prediction"]["ham_prediction"] = $UserStatus->GeneralizedHam;
                        $ResponsePayload["results"]["spam_prediction"]["spam_prediction"] = $UserStatus->GeneralizedSpam;
                    }

                    if($UserStatus->IsBlacklisted)
                    {
                        $ResponsePayload["results"]["attributes"]["is_blacklisted"] = true;
                        $ResponsePayload["results"]["attributes"]["blacklist_flag"] = $UserStatus->BlacklistFlag;
                        $ResponsePayload["results"]["attributes"]["blacklist_reason"] = self::blacklistFlagToReason($UserStatus->BlacklistFlag);
                        $ResponsePayload["results"]["attributes"]["original_private_id"] = $UserStatus->OriginalPrivateID;
                    }

                    if($TargetTelegramClient->User->IsBot == false)
                    {
                        if($UserStatus->GeneralizedID !== "None" && $UserStatus->GeneralizedID !== null)
                        {
                            if($UserStatus->GeneralizedHam > 0)
                            {
                                if($UserStatus->GeneralizedSpam > $UserStatus->GeneralizedHam)
                                {
                                    $ResponsePayload["results"]["attributes"]["is_potential_spammer"] = true;
                                }
                            }
                        }
                    }

                    if($UserStatus->IsOperator)
                    {
                        $ResponsePayload["results"]["attributes"]["is_operator"] = true;
                    }

                    if($UserStatus->IsAgent)
                    {
                        $ResponsePayload["results"]["attributes"]["is_agent"] = true;
                    }

                    if($UserStatus->IsWhitelisted)
                    {
                        $ResponsePayload["results"]["attributes"]["is_whitelisted"] = true;
                    }

                    if($TargetTelegramClient->AccountID !== null && $TargetTelegramClient->AccountID !== 0)
                    {
                        $ResponsePayload["results"]["attributes"]["intellivoid_accounts_verified"] = true;
                    }
                    break;

                case TelegramChatType::Group:
                case TelegramChatType::SuperGroup:

                    $ChatSettings = SettingsManager::getChatSettings($TargetTelegramClient);

                    if($ChatSettings->LargeLanguageGeneralizedID !== null)
                    {
                        $ResponsePayload["results"]["language_prediction"]["language"] = $ChatSettings->GeneralizedLanguage;
                        $ResponsePayload["results"]["language_prediction"]["probability"] = $ChatSettings->GeneralizedLanguageProbability;
                    }

                    if($ChatSettings->IsVerified)
                    {
                        $ResponsePayload["results"]["attributes"]["is_official"] = true;
                    }

                    break;

                case TelegramChatType::Channel:

                    $ChannelStatus = SettingsManager::getChannelStatus($TargetTelegramClient);

                    if($ChannelStatus->LargeLanguageGeneralizedID !== null)
                    {
                        $ResponsePayload["results"]["language_prediction"]["language"] = $ChannelStatus->GeneralizedLanguage;
                        $ResponsePayload["results"]["language_prediction"]["probability"] = $ChannelStatus->GeneralizedLanguageProbability;
                    }

                    if($ChannelStatus->IsOfficial)
                    {
                        $ResponsePayload["results"]["attributes"]["is_official"] = true;
                    }

                    if($ChannelStatus->IsWhitelisted)
                    {
                        $ResponsePayload["results"]["attributes"]["is_whitelisted"] = true;
                    }

                    if($ChannelStatus->IsBlacklisted)
                    {
                        $ResponsePayload["results"]["attributes"]["is_blacklisted"] = true;
                        $ResponsePayload["results"]["attributes"]["blacklist_flag"] = $ChannelStatus->BlacklistFlag;
                        $ResponsePayload["results"]["attributes"]["blacklist_reason"] = self::blacklistFlagToReason($ChannelStatus->BlacklistFlag);
                        $ResponsePayload["results"]["attributes"]["original_private_id"] = null;
                    }

                    if($ChannelStatus->GeneralizedID !== "None" && $ChannelStatus->GeneralizedID !== null)
                    {
                        if($ChannelStatus->GeneralizedHam > 0)
                        {
                            if($ChannelStatus->GeneralizedSpam > $ChannelStatus->GeneralizedHam)
                            {
                                $ResponsePayload["results"]["attributes"]["is_potential_spammer"] = true;
                            }
                        }
                    }

                    if($ChannelStatus->GeneralizedID !== "None" && $ChannelStatus->GeneralizedID !== null)
                    {
                        $ResponsePayload["results"]["spam_prediction"]["ham_prediction"] = $ChannelStatus->GeneralizedHam;
                        $ResponsePayload["results"]["spam_prediction"]["spam_prediction"] = $ChannelStatus->GeneralizedSpam;
                    }

                    break;

                default:
                    break;
            }

            $this->response_content = json_encode($ResponsePayload);
            $this->response_code = (int)$ResponsePayload["response_code"];
            return null;
        }

        /**
         * Takes a blacklist flag and converts it into a user-readable message
         *
         * @param string $flag
         * @return string
         */
        public static function blacklistFlagToReason(string $flag): string
        {
            switch($flag)
            {
                case BlacklistFlag::None:
                    return "None";

                case BlacklistFlag::Spam:
                    return "Spam / Unwanted Promotion";

                case BlacklistFlag::BanEvade:
                    return "Ban Evade";

                case BlacklistFlag::ChildAbuse:
                    return "Child Pornography / Child Abuse";

                case BlacklistFlag::Impersonator:
                    return "Malicious Impersonator";

                case BlacklistFlag::PiracySpam:
                    return "Promotes/Spam Pirated Content";

                case BlacklistFlag::PornographicSpam:
                    return "Promotes/Spam NSFW Content";

                case BlacklistFlag::PrivateSpam:
                    return "Spam / Unwanted Promotion via a unsolicited private message";

                case BlacklistFlag::Raid:
                    return "RAID Initializer / Participator";

                case BlacklistFlag::Scam:
                    return "Scamming";

                case BlacklistFlag::Special:
                    return "Special Reason, consult main operators in @SpamProtectionSupport";

                case BlacklistFlag::MassAdding:
                    return "Mass adding users to groups/channels";

                case BlacklistFlag::NameSpam:
                    return "Promotion/Spam via Name or Bio";

                default:
                    return "Unknown";
            }
        }

    }