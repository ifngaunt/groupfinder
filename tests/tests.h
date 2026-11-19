#pragma once
// Factories for every QtTest class; tests/test_main.cpp runs them all in one executable.
class QObject;

QObject* createTestSchedule();
QObject* createTestMeeting();
QObject* createTestFiring();
QObject* createTestGroupQuery();
