<?php


    namespace Handler\Objects;

    /**
     * Class VersionConfiguration
     * @package Handler\Objects
     */
    class VersionConfiguration
    {
        /**
         * The version of this configuration
         *
         * @var string
         */
        public $Version;

        /**
         * Indicates if the version is available or not
         *
         * @var bool
         */
        public $Available;

        /**
         * The message to display if the version is unavailable
         *
         * @var string
         */
        public $UnavailableMessage;

        /**
         * Array of library objects
         *
         * @var Library[]
         */
        public $Libraries;

        /**
         * List of required PPM modules
         *
         * @var PpmDependency[]
         */
        public $PpmPackages;

        /**
         * Array of module objects
         *
         * @var array
         */
        public $Modules;

        /**
         * Returns an array which represents the object
         *
         * @return array
         */
        public function toArray(): array
        {
            $libraries = array();
            $modules = array();
            $ppm_packages = array();

            foreach($this->Libraries as $library)
            {
                $libraries[$library->Name] = $library->toArray(false);
            }

            foreach($this->PpmPackages as $package)
            {
                $ppm_packages[] = $package->toArray();
            }

            /** @var ModuleConfiguration $module */
            foreach($this->Modules as $module_name => $module)
            {
                $modules[] = $module->toArray();
            }

            return array(
                'VERSION' => $this->Version,
                'AVAILABLE' => (bool)$this->Available,
                'UNAVAILABLE_MESSAGE' => $this->UnavailableMessage,
                'LIBRARIES' => $libraries,
                'PPM' => $ppm_packages,
                'MODULES' => $modules
            );
        }

        /**
         * Constructs object from array
         *
         * @param array $data
         * @return VersionConfiguration
         */
        public static function fromArray(array $data): VersionConfiguration
        {
            $VersionConfigurationObject = new VersionConfiguration();

            if(isset($data['VERSION']))
            {
                $VersionConfigurationObject->Version = $data['VERSION'];
            }

            if(isset($data['AVAILABLE']))
            {
                $VersionConfigurationObject->Available = (bool)$data['AVAILABLE'];
            }

            if(isset($data['UNAVAILABLE_MESSAGE']))
            {
                $VersionConfigurationObject->UnavailableMessage = $data['UNAVAILABLE_MESSAGE'];
            }

            if(isset($data['LIBRARIES']))
            {
                foreach($data['LIBRARIES'] as $library_name => $configuration)
                {
                    $LibraryConfiguration = Library::fromArray($configuration, $library_name);
                    $VersionConfigurationObject->Libraries[$library_name] = $LibraryConfiguration;
                }
            }

            if(isset($data['PPM']))
            {
                $VersionConfigurationObject->PpmPackages = [];

                foreach($data['PPM'] as $datum)
                {
                    $VersionConfigurationObject->PpmPackages[] = PpmDependency::fromArray($datum);
                }
            }

            if(isset($data['MODULES']))
            {
                foreach($data['MODULES'] as $module_configuration)
                {
                    $ModuleConfiguration = ModuleConfiguration::fromArray($module_configuration);
                    $VersionConfigurationObject->Modules[$ModuleConfiguration->Script] = $ModuleConfiguration;
                }
            }

            return $VersionConfigurationObject;
        }
    }