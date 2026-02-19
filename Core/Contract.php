<?php

/**
 * This file is part of simple-web3-php package.
 *
 * (c) Alex Cabrera
 *
 * @author Alex Cabrera
 * @license MIT
 */

namespace iAmirNet\SWeb3;


use iAmirNet\SWeb3\SWeb3;
use iAmirNet\SWeb3\Utils;
use Exception;

class Contract
{
    public $sweb3;
    public $ABI;
    public $address;
    public $bytecode;


    function __construct(SWeb3 $sweb3, string $contractAddress, $contractABI)
    {
        $this->sweb3 = $sweb3;
        $this->address = $contractAddress;

        $this->ABI = new ABI();
        $this->ABI->Init($contractABI);
    }

    public function getABI(): ABI
    {
        return $this->ABI;
    }

    public function setBytecode($bytecode)
    {
        $this->bytecode = $bytecode;
    }


    public function call(string $function_name, $callData = null, $extraParams = null, $blockNumber = 'latest')
    {
        if ($extraParams == null) $extraParams = [];
        if (!empty($extraParams['to']))
            $extraParams['to'] = $this->address;
        $extraParams['data'] = $this->encode($function_name, $callData);
        $result = $this->sweb3->call('eth_call', [$extraParams], $blockNumber);
        return isset($result->result) ? $this->decode($function_name, $result->result) : $result;
    }

    public function send(string $function_name, $sendData, $extraParams = null)
    {
        if ($extraParams == null) $extraParams = [];
        if (!empty($extraParams['from']))
            $extraParams['from'] = $this->sweb3->personal->address;
        if (!empty($extraParams['to']))
            $extraParams['to'] = $this->address;
        $extraParams['data'] = $this->encode($function_name, $sendData);
        if (empty($extraParams['gasLimit']) && empty($extraParams['gas']))
            $extraParams['gasLimit'] = $this->estimateGas($extraParams);
        $result = $this->sweb3->send($extraParams);
        isset($result->result) ? $this->decode($function_name, $result->result) : $result;
    }


    public function decode(string $function_name, $data)
    {
        return $this->ABI->DecodeData($function_name, $data);
    }


    public function encode(string $function_name, $data)
    {
        return $this->ABI->EncodeData($function_name, $data);
    }

    public function estimateGas($extraParams)
    {
        $gasEstimateResult = $this->sweb3->call('eth_estimateGas', [$extraParams]);
        if (!isset($gasEstimateResult->result))
            throw new Exception('ERROR: estimateGas error: ' . $gasEstimateResult->error->message . ' (' . $gasEstimateResult->error->code . ')');
        return $this->sweb3->utils->hexToBn($gasEstimateResult->result);
    }


    public function deployContract(array $inputs = [], array $extra_params = [])
    {
        if (!isset($this->bytecode)) {
            throw new Exception('ERROR: you need to initialize bytecode to deploy the contract');
        }

        $count_expected = isset($this->ABI->constructor) && isset($this->ABI->constructor->inputs) ? count($this->ABI->constructor->inputs) : 0;
        $count_received = count($inputs);
        if ($count_expected != $count_received) {
            throw new Exception('ERROR: contract constructor inputs number does not match... Expecting: ' . $count_expected . ' Received: ' . $count_received);
        }

        $inputEncoded = $this->encode('', $inputs);
        $extra_params['data'] = '0x' . $this->bytecode . Utils::stripZero($inputEncoded);

        //get function estimateGas
        if (!isset($extra_params['gasLimit'])) {
            $gasEstimateResult = $this->sweb3->call('eth_estimateGas', [$extra_params]);

            if (!isset($gasEstimateResult->result))
                throw new Exception('estimation error: ' . json_encode($gasEstimateResult));

            $extra_params['gasLimit'] = $this->sweb3->utils->hexToBn($gasEstimateResult->result);
        }

        //get gas price
        if (!isset($extra_params['gasPrice'])) $extra_params['gasPrice'] = $this->sweb3->getGasPrice();

        return $this->sweb3->send($extra_params);
    }


    //EVENT LOGS

    //returns event ABI from event hash (encoded event name in transaction logs -> topics[0])
    public function GetEventFromLog($log_object)
    {
        return $this->ABI->GetEventFromHash($log_object->topics[0]);
    }


    //returns decoded topics/data from event object (in transaction logs )
    public function DecodeEvent($event_object, $log)
    {
        return $this->ABI->DecodeEvent($event_object, $log);
    }


    //returns all event logs. each with 2 extra parameters "decoded_data" and "event_anme"
    public function getLogs(string $minBlock = null, string $maxBlock = null, $topics = null)
    {
        $result = $this->sweb3->getLogs($this->address, $minBlock, $maxBlock, $topics);
        $logs = $result->result;

        foreach ($logs as $log) {
            $event = $this->GetEventFromLog($log);
            if ($event != null) {
                $log->event_name = $event->name;
                $log->decoded_data = $this->DecodeEvent($event, $log);
            } else {
                $log->event_name = 'unknown';
            }
        }

        return $logs;
    }
}
