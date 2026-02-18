<?php

namespace iAmirNet\SWeb3;

class PersonalData
{
    private $sweb3;
    public $address;
    public $privateKey;

    function __construct(SWeb3 $sweb3, string $address, string $privateKey)
    {
        $this->sweb3 = $sweb3;
        $this->address = $address;
        $this->privateKey = $privateKey;
    }

    function getNonce()
    {
        return $this->sweb3->getNonce($this->address);
    }
}
