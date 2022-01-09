<?php

    /** @noinspection PhpUnused */
    /** @noinspection PhpIllegalPsrClassPathInspection */

    namespace Methods\v1;

    use KimchiAPI\Abstracts\Method;
    use KimchiAPI\Abstracts\ResponseStandard;
    use KimchiAPI\Classes\Request;
    use KimchiAPI\Objects\Response;
    use SpamProtection\Abstracts\BlacklistFlag;
    use SpamProtection\Managers\SettingsManager;
    use SpamProtection\Utilities\Hashing;
    use TelegramClientManager\Abstracts\SearchMethods\TelegramClientSearchMethod;
    use TelegramClientManager\Abstracts\TelegramChatType;
    use TelegramClientManager\Exceptions\DatabaseException;
    use TelegramClientManager\Exceptions\InvalidSearchMethod;
    use TelegramClientManager\Exceptions\TelegramClientNotFoundException;
    use TelegramClientManager\TelegramClientManager;

    /**
     * Class lookup_user
     */
    class LookupUserMethod extends Method
    {

        /**
         * @return Response
         * @throws DatabaseException
         * @throws InvalidSearchMethod
         */
        public function execute(): Response
        {
            $Parameters = Request::getParameters();

            if(isset($Parameters["query"]) == false)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorMessage = "Missing parameter 'query'";
                $Response->ErrorCode = 0;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
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
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 404;
                $Response->ErrorMessage = "Unable to resolve the query";
                $Response->ErrorCode = 10;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
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

            $Response = new Response();
            $Response->Success = true;
            $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
            $Response->ResultData = [
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
                "last_updated" => $TargetTelegramClient->LastActivityTimestamp
            ];

            switch($TargetTelegramClient->Chat->Type)
            {
                case TelegramChatType::Private:
                case "user":
                case "bot":
                    $UserStatus = SettingsManager::getUserStatus($TargetTelegramClient);

                    if($UserStatus->LargeLanguageGeneralizedID !== null)
                    {
                        $Response->ResultData["language_prediction"]["language"] = $UserStatus->GeneralizedLanguage;
                        $Response->ResultData["language_prediction"]["probability"] = $UserStatus->GeneralizedLanguageProbability;
                    }

                    if($UserStatus->GeneralizedID !== "None" && $UserStatus->GeneralizedID !== null)
                    {
                        $Response->ResultData["spam_prediction"]["ham_prediction"] = $UserStatus->GeneralizedHam;
                        $Response->ResultData["spam_prediction"]["spam_prediction"] = $UserStatus->GeneralizedSpam;
                    }

                    if($UserStatus->IsBlacklisted)
                    {
                        $Response->ResultData["attributes"]["is_blacklisted"] = true;
                        $Response->ResultData["attributes"]["blacklist_flag"] = $UserStatus->BlacklistFlag;
                        $Response->ResultData["attributes"]["blacklist_reason"] = self::blacklistFlagToReason($UserStatus->BlacklistFlag);
                        $Response->ResultData["attributes"]["original_private_id"] = $UserStatus->OriginalPrivateID;
                    }

                    if($TargetTelegramClient->User->IsBot == false)
                    {
                        if($UserStatus->GeneralizedID !== "None" && $UserStatus->GeneralizedID !== null)
                        {
                            if($UserStatus->GeneralizedHam > 0)
                            {
                                if($UserStatus->GeneralizedSpam > $UserStatus->GeneralizedHam)
                                {
                                    $Response->ResultData["attributes"]["is_potential_spammer"] = true;
                                }
                            }
                        }
                    }

                    if($UserStatus->IsOperator)
                    {
                        $Response->ResultData["attributes"]["is_operator"] = true;
                    }

                    if($UserStatus->IsAgent)
                    {
                        $Response->ResultData["attributes"]["is_agent"] = true;
                    }

                    if($UserStatus->IsWhitelisted)
                    {
                        $Response->ResultData["attributes"]["is_whitelisted"] = true;
                    }

                    if($TargetTelegramClient->AccountID !== null && $TargetTelegramClient->AccountID !== 0)
                    {
                        $Response->ResultData["attributes"]["intellivoid_accounts_verified"] = true;
                    }
                    break;

                case TelegramChatType::Group:
                case TelegramChatType::SuperGroup:

                    $ChatSettings = SettingsManager::getChatSettings($TargetTelegramClient);

                    if($ChatSettings->LargeLanguageGeneralizedID !== null)
                    {
                        $Response->ResultData["language_prediction"]["language"] = $ChatSettings->GeneralizedLanguage;
                        $Response->ResultData["language_prediction"]["probability"] = $ChatSettings->GeneralizedLanguageProbability;
                    }

                    if($ChatSettings->IsVerified)
                    {
                        $Response->ResultData["attributes"]["is_official"] = true;
                    }

                    break;

                case TelegramChatType::Channel:

                    $ChannelStatus = SettingsManager::getChannelStatus($TargetTelegramClient);

                    if($ChannelStatus->LargeLanguageGeneralizedID !== null)
                    {
                        $Response->ResultData["language_prediction"]["language"] = $ChannelStatus->GeneralizedLanguage;
                        $Response->ResultData["language_prediction"]["probability"] = $ChannelStatus->GeneralizedLanguageProbability;
                    }

                    if($ChannelStatus->IsOfficial)
                    {
                        $Response->ResultData["attributes"]["is_official"] = true;
                    }

                    if($ChannelStatus->IsWhitelisted)
                    {
                        $Response->ResultData["attributes"]["is_whitelisted"] = true;
                    }

                    if($ChannelStatus->IsBlacklisted)
                    {
                        $Response->ResultData["attributes"]["is_blacklisted"] = true;
                        $Response->ResultData["attributes"]["blacklist_flag"] = $ChannelStatus->BlacklistFlag;
                        $Response->ResultData["attributes"]["blacklist_reason"] = self::blacklistFlagToReason($ChannelStatus->BlacklistFlag);
                        $Response->ResultData["attributes"]["original_private_id"] = null;
                    }

                    if($ChannelStatus->GeneralizedID !== "None" && $ChannelStatus->GeneralizedID !== null)
                    {
                        if($ChannelStatus->GeneralizedHam > 0)
                        {
                            if($ChannelStatus->GeneralizedSpam > $ChannelStatus->GeneralizedHam)
                            {
                                $Response->ResultData["attributes"]["is_potential_spammer"] = true;
                            }
                        }
                    }

                    if($ChannelStatus->GeneralizedID !== "None" && $ChannelStatus->GeneralizedID !== null)
                    {
                        $Response->ResultData["spam_prediction"]["ham_prediction"] = $ChannelStatus->GeneralizedHam;
                        $Response->ResultData["spam_prediction"]["spam_prediction"] = $ChannelStatus->GeneralizedSpam;
                    }

                    break;

                default:
                    break;
            }

            return $Response;
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